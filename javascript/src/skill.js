/**
 * Skill folder signing and verification for SchemaPin v1.3 / v1.4.
 *
 * Extends SchemaPin's ECDSA P-256 signing to cover file-based skill folders
 * (AgentSkills spec). Same keys, same .well-known discovery, new canonicalization
 * target.
 *
 * v1.4 additions (additive, optional, backward-compatible):
 *   - `expires_at` field on `.schemapin.sig` via {@link signSkillWithOptions}.
 *   - DNS TXT cross-verification via {@link verifySkillOfflineWithDns}.
 */

import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { readFileSync, readdirSync, writeFileSync, lstatSync, existsSync } from 'node:fs';
import { join, relative, basename, resolve } from 'node:path';
import { KeyManager, SignatureManager } from './crypto.js';
import { checkRevocationCombined } from './revocation.js';
import { ErrorCode, applyExpirationCheck } from './verification.js';
import { verifyDnsMatch } from './dns.js';

export const SIGNATURE_FILENAME = '.schemapin.sig';
const SCHEMAPIN_VERSION_V13 = '1.3';
const SCHEMAPIN_VERSION_V14 = '1.4';

/**
 * Format a Date as RFC 3339 UTC with seconds precision and `Z` suffix.
 * Mirrors Rust's `chrono::SecondsFormat::Secs` rendering.
 *
 * @param {Date} date
 * @returns {string} e.g. `2026-04-30T21:41:50Z`
 */
function toRfc3339Seconds(date) {
    const iso = date.toISOString(); // 2026-04-30T21:41:50.123Z
    return iso.replace(/\.\d{3}Z$/, 'Z');
}

/**
 * Recursively walk a directory in sorted order, collecting file entries.
 *
 * @param {string} dir - Current directory to walk
 * @param {string} baseDir - Root skill directory for computing relative paths
 * @param {Object} manifest - Accumulator for manifest entries
 */
function walkSorted(dir, baseDir, manifest) {
    const entries = readdirSync(dir, { withFileTypes: true });
    // Separate dirs and files, sort each by name
    const dirs = [];
    const files = [];
    for (const entry of entries) {
        if (entry.isDirectory()) {
            dirs.push(entry.name);
        } else {
            files.push(entry.name);
        }
    }
    dirs.sort();
    files.sort();

    // Process files first (matching Python os.walk behavior within each directory)
    for (const fname of files) {
        if (fname === SIGNATURE_FILENAME) {
            continue;
        }
        const fullPath = join(dir, fname);
        // Skip symlinks
        const lstats = lstatSync(fullPath);
        if (lstats.isSymbolicLink()) {
            continue;
        }
        const relPath = relative(baseDir, fullPath).split('\\').join('/');
        const fileBytes = readFileSync(fullPath);
        const pathBytes = Buffer.from(relPath, 'utf-8');
        const digest = createHash('sha256')
            .update(pathBytes)
            .update(fileBytes)
            .digest('hex');
        manifest[relPath] = `sha256:${digest}`;
    }

    // Recurse into subdirectories in sorted order
    for (const dname of dirs) {
        const subdir = join(dir, dname);
        // Skip symlinked directories
        const lstats = lstatSync(subdir);
        if (lstats.isSymbolicLink()) {
            continue;
        }
        walkSorted(subdir, baseDir, manifest);
    }
}

/**
 * Canonicalize a skill directory deterministically and compute a root hash.
 *
 * Algorithm:
 *   1. Recursive sorted walk via readdirSync
 *   2. Skip .schemapin.sig and symlinks
 *   3. Normalize paths to forward slashes
 *   4. Per-file: sha256(rel_path_utf8 + file_bytes).hexdigest()
 *   5. Root: sha256(concat of all hexdigests, sorted by rel_path).digest()
 *
 * @param {string} skillDir - Path to skill directory
 * @returns {{ rootHash: Buffer, manifest: Object }} Root hash and file manifest
 * @throws {Error} If directory is empty or contains no signable files
 */
export function canonicalizeSkill(skillDir) {
    const skillPath = resolve(skillDir);
    const manifest = {};

    walkSorted(skillPath, skillPath, manifest);

    if (Object.keys(manifest).length === 0) {
        throw new Error(`Skill directory is empty or contains no signable files: ${skillDir}`);
    }

    // Root hash: sort manifest keys, extract hex digests, concatenate, sha256
    const sortedKeys = Object.keys(manifest).sort();
    const sortedDigests = sortedKeys.map(k => {
        const parts = manifest[k].split(':');
        return parts.slice(1).join(':');
    });
    const rootHash = createHash('sha256')
        .update(sortedDigests.join(''), 'utf-8')
        .digest();

    return { rootHash, manifest };
}

/**
 * Extract the skill name from SKILL.md frontmatter.
 *
 * Falls back to the directory basename if SKILL.md is missing or
 * has no name: field.
 *
 * @param {string} skillDir - Path to skill directory
 * @returns {string} Skill name
 */
export function parseSkillName(skillDir) {
    const skillPath = resolve(skillDir);
    const skillMd = join(skillPath, 'SKILL.md');

    if (existsSync(skillMd)) {
        try {
            const text = readFileSync(skillMd, 'utf-8');
            const fmMatch = text.match(/^---\s*\n([\s\S]*?)\n---/);
            if (fmMatch) {
                const frontmatter = fmMatch[1];
                const nameMatch = frontmatter.match(/^name:\s*['"]?([^'"#\n]+?)['"]?\s*$/m);
                if (nameMatch) {
                    return nameMatch[1].trim();
                }
            }
        } catch {
            // Fall through to basename
        }
    }

    return basename(skillPath);
}

/**
 * Read and parse the .schemapin.sig file from a skill directory.
 *
 * @param {string} skillDir - Path to skill directory
 * @returns {Object} Parsed signature document
 * @throws {Error} If .schemapin.sig does not exist
 */
export function loadSignature(skillDir) {
    const sigPath = join(resolve(skillDir), SIGNATURE_FILENAME);
    if (!existsSync(sigPath)) {
        throw new Error(`Signature file not found: ${sigPath}`);
    }
    const text = readFileSync(sigPath, 'utf-8');
    return JSON.parse(text);
}

/**
 * Canonicalize a skill directory, sign, and write .schemapin.sig.
 *
 * v1.3 entry point. Preserved for backward compatibility — internally this is
 * a thin wrapper over {@link signSkillWithOptions}.
 *
 * @param {string} skillDir - Path to the skill folder
 * @param {string} privateKeyPem - PEM-encoded ECDSA P-256 private key
 * @param {string} domain - Signing domain (e.g. "thirdkey.ai")
 * @param {string|null} signerKid - Optional key ID (fingerprint). Auto-computed if null.
 * @param {string|null} skillName - Override for the skill name. Parsed from SKILL.md if not provided.
 * @returns {Object} The signature document that was written
 */
export function signSkill(skillDir, privateKeyPem, domain, signerKid = null, skillName = null) {
    return signSkillWithOptions(skillDir, privateKeyPem, domain, {
        signerKid,
        skillName
    });
}

/**
 * Canonicalize a skill directory, sign, and write .schemapin.sig with extended
 * options (v1.4+).
 *
 * When `options.expiresIn` is set (milliseconds), an `expires_at` ISO 8601
 * timestamp (RFC 3339 with `Z` suffix, second precision) is written and the
 * `schemapin_version` field is bumped from `"1.3"` to `"1.4"`. Verifiers past
 * that timestamp emit a `signature_expired` warning instead of failing — see
 * {@link verifySkillOffline}.
 *
 * Options:
 *   - `signerKid` - Override the signer key id (KID). Defaults to the
 *     discovery fingerprint of the public key.
 *   - `skillName` - Override the skill name. Defaults to the SKILL.md
 *     frontmatter `name:` or directory basename.
 *   - `expiresIn` - Time-to-live for the signature, in milliseconds. When set,
 *     an `expires_at` field is written.
 *
 * @param {string} skillDir - Path to the skill folder
 * @param {string} privateKeyPem - PEM-encoded ECDSA P-256 private key
 * @param {string} domain - Signing domain
 * @param {{ signerKid?: string|null, skillName?: string|null, expiresIn?: number|null }} [options]
 * @returns {Object} The signature document that was written
 */
export function signSkillWithOptions(skillDir, privateKeyPem, domain, options = {}) {
    const { signerKid: optSignerKid = null, skillName: optSkillName = null, expiresIn = null } = options;

    const skillPath = resolve(skillDir);
    const privateKey = KeyManager.loadPrivateKeyPem(privateKeyPem);

    // Derive public key PEM from private key
    const privKeyObj = createPrivateKey(privateKeyPem);
    const pubKeyObj = createPublicKey(privKeyObj);
    const publicKeyPem = pubKeyObj.export({ type: 'spki', format: 'pem' });

    const { rootHash, manifest } = canonicalizeSkill(skillPath);

    const skillName = (optSkillName === null || optSkillName === undefined)
        ? parseSkillName(skillPath)
        : optSkillName;

    const signerKid = (optSignerKid === null || optSignerKid === undefined)
        ? KeyManager.calculateKeyFingerprint(publicKeyPem)
        : optSignerKid;

    const signatureB64 = SignatureManager.signHash(rootHash, privateKey);

    const now = new Date();
    let expiresAt = null;
    if (expiresIn !== null && expiresIn !== undefined) {
        expiresAt = toRfc3339Seconds(new Date(now.getTime() + expiresIn));
    }

    const version = expiresAt !== null ? SCHEMAPIN_VERSION_V14 : SCHEMAPIN_VERSION_V13;

    const sigDoc = {
        schemapin_version: version,
        skill_name: skillName,
        skill_hash: `sha256:${rootHash.toString('hex')}`,
        signature: signatureB64,
        signed_at: toRfc3339Seconds(now),
        domain: domain,
        signer_kid: signerKid,
        file_manifest: manifest
    };
    if (expiresAt !== null) {
        // Insert expires_at after signed_at to keep field order stable.
        sigDoc.expires_at = expiresAt;
        // Re-serialize in the documented field order.
        const ordered = {
            schemapin_version: sigDoc.schemapin_version,
            skill_name: sigDoc.skill_name,
            skill_hash: sigDoc.skill_hash,
            signature: sigDoc.signature,
            signed_at: sigDoc.signed_at,
            expires_at: sigDoc.expires_at,
            domain: sigDoc.domain,
            signer_kid: sigDoc.signer_kid,
            file_manifest: sigDoc.file_manifest
        };
        const sigPath = join(skillPath, SIGNATURE_FILENAME);
        writeFileSync(sigPath, JSON.stringify(ordered, null, 2) + '\n', 'utf-8');
        return ordered;
    }

    const sigPath = join(skillPath, SIGNATURE_FILENAME);
    writeFileSync(sigPath, JSON.stringify(sigDoc, null, 2) + '\n', 'utf-8');

    return sigDoc;
}

/**
 * Verify a signed skill folder offline (7-step flow).
 *
 * Mirrors verifySchemaOffline():
 *   1. Load or accept signature data
 *   2. Validate discovery document
 *   3. Extract public key and compute fingerprint
 *   4. Check revocation
 *   5. TOFU key pinning
 *   6. Canonicalize skill and verify ECDSA signature
 *   7. Return structured result
 *
 * @param {string} skillDir - Path to skill directory
 * @param {Object} discovery - Well-known discovery document
 * @param {Object|null} signatureData - Pre-loaded signature data (loads from file if null)
 * @param {Object|null} revocationDoc - Standalone revocation document
 * @param {KeyPinStore|null} pinStore - TOFU pin store
 * @param {string|null} toolId - Tool identifier for pinning
 * @returns {Object} Verification result
 */
export function verifySkillOffline(skillDir, discovery, signatureData = null, revocationDoc = null, pinStore = null, toolId = null) {
    const skillPath = resolve(skillDir);

    // Step 1: Load signature data
    if (signatureData === null || signatureData === undefined) {
        try {
            signatureData = loadSignature(skillPath);
        } catch {
            return {
                valid: false,
                error_code: ErrorCode.SIGNATURE_INVALID,
                error_message: 'No .schemapin.sig found in skill directory'
            };
        }
    }

    const domain = signatureData.domain || '';
    if (toolId === null || toolId === undefined) {
        toolId = signatureData.skill_name || basename(skillPath);
    }

    // Step 2: Validate discovery document
    const publicKeyPem = discovery?.public_key_pem;
    if (!publicKeyPem || !publicKeyPem.includes('-----BEGIN PUBLIC KEY-----')) {
        return {
            valid: false,
            domain,
            error_code: ErrorCode.DISCOVERY_INVALID,
            error_message: 'Discovery document missing or invalid public_key_pem'
        };
    }

    // Step 3: Extract public key and compute fingerprint
    let publicKey, fingerprint;
    try {
        publicKey = KeyManager.loadPublicKeyPem(publicKeyPem);
        fingerprint = KeyManager.calculateKeyFingerprint(publicKeyPem);
    } catch (e) {
        return {
            valid: false,
            domain,
            error_code: ErrorCode.KEY_NOT_FOUND,
            error_message: `Failed to load public key: ${e.message}`
        };
    }

    // Step 4: Check revocation
    const simpleRevoked = discovery.revoked_keys || [];
    try {
        checkRevocationCombined(simpleRevoked, revocationDoc, fingerprint);
    } catch (e) {
        return {
            valid: false,
            domain,
            error_code: ErrorCode.KEY_REVOKED,
            error_message: e.message
        };
    }

    // Step 5: TOFU key pinning
    let pinResult = null;
    if (pinStore !== null && pinStore !== undefined) {
        pinResult = pinStore.checkAndPin(toolId, domain, fingerprint);
        if (pinResult === 'changed') {
            return {
                valid: false,
                domain,
                error_code: ErrorCode.KEY_PIN_MISMATCH,
                error_message: 'Key fingerprint changed since last use'
            };
        }
    }

    // Step 6: Canonicalize and verify signature
    let rootHash;
    try {
        const result = canonicalizeSkill(skillPath);
        rootHash = result.rootHash;
    } catch (e) {
        return {
            valid: false,
            domain,
            error_code: ErrorCode.SCHEMA_CANONICALIZATION_FAILED,
            error_message: `Failed to canonicalize skill: ${e.message}`
        };
    }

    const signatureB64 = signatureData.signature || '';
    const valid = SignatureManager.verifySignature(rootHash, signatureB64, publicKey);

    if (!valid) {
        return {
            valid: false,
            domain,
            error_code: ErrorCode.SIGNATURE_INVALID,
            error_message: 'Signature verification failed'
        };
    }

    // Step 7: Return success
    const resultObj = {
        valid: true,
        domain,
        developer_name: discovery.developer_name || null,
        key_pinning: pinResult ? { status: pinResult } : null,
        warnings: []
    };

    // v1.4: apply signature expiration check (degraded, not failed).
    if (signatureData.expires_at !== null && signatureData.expires_at !== undefined) {
        applyExpirationCheck(resultObj, signatureData.expires_at);
    }

    return resultObj;
}

/**
 * Verify a signed skill folder offline with an optional DNS TXT cross-check (v1.4).
 *
 * Behaves identically to {@link verifySkillOffline}, then — when `dnsTxt` is
 * non-null — verifies that the DNS TXT record's fingerprint matches the
 * discovery key. A mismatch converts the result into a hard failure with
 * `ErrorCode.DOMAIN_MISMATCH`. When `dnsTxt` is null, behaviour is unchanged
 * (DNS TXT is an optional, additive trust signal).
 *
 * @param {string} skillDir - Path to skill directory
 * @param {Object} discovery - Well-known discovery document
 * @param {Object|null} signatureData - Pre-loaded signature data (loads from file if null)
 * @param {Object|null} revocationDoc - Standalone revocation document
 * @param {KeyPinStore|null} pinStore - TOFU pin store
 * @param {string|null} toolId - Tool identifier for pinning
 * @param {Object|null} dnsTxt - Parsed DNS TXT record (`{ version, kid, fingerprint }`)
 * @returns {Object} Verification result
 */
export function verifySkillOfflineWithDns(skillDir, discovery, signatureData = null, revocationDoc = null, pinStore = null, toolId = null, dnsTxt = null) {
    const result = verifySkillOffline(skillDir, discovery, signatureData, revocationDoc, pinStore, toolId);

    if (!result.valid) {
        return result;
    }
    if (dnsTxt === null || dnsTxt === undefined) {
        return result;
    }
    try {
        verifyDnsMatch(discovery, dnsTxt);
        return result;
    } catch (e) {
        return {
            valid: false,
            domain: result.domain,
            error_code: ErrorCode.DOMAIN_MISMATCH,
            error_message: e.message
        };
    }
}

/**
 * Verify a signed skill folder using a resolver for discovery.
 *
 * @param {string} skillDir - Path to skill directory
 * @param {string} domain - Domain to resolve discovery for
 * @param {Object} resolver - SchemaResolver instance
 * @param {KeyPinStore|null} pinStore - TOFU pin store
 * @param {string|null} toolId - Tool identifier for pinning
 * @returns {Promise<Object>} Verification result
 */
export async function verifySkillWithResolver(skillDir, domain, resolver, pinStore = null, toolId = null) {
    const discovery = await resolver.resolveDiscovery(domain);
    if (!discovery) {
        return {
            valid: false,
            domain,
            error_code: ErrorCode.DISCOVERY_FETCH_FAILED,
            error_message: `Could not resolve discovery for domain: ${domain}`
        };
    }

    const revocation = await resolver.resolveRevocation(domain, discovery);

    return verifySkillOffline(skillDir, discovery, null, revocation, pinStore, toolId);
}

/**
 * Compare current file manifest against the signed manifest.
 *
 * @param {Object} currentManifest - Current file manifest
 * @param {Object} signedManifest - Signed file manifest
 * @returns {{ modified: string[], added: string[], removed: string[] }}
 */
export function detectTamperedFiles(currentManifest, signedManifest) {
    const currentKeys = new Set(Object.keys(currentManifest));
    const signedKeys = new Set(Object.keys(signedManifest));

    const added = [...currentKeys].filter(k => !signedKeys.has(k)).sort();
    const removed = [...signedKeys].filter(k => !currentKeys.has(k)).sort();
    const modified = [...currentKeys]
        .filter(k => signedKeys.has(k) && currentManifest[k] !== signedManifest[k])
        .sort();

    return { modified, added, removed };
}
