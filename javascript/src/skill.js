/**
 * Skill folder signing and verification for SchemaPin v1.3.
 *
 * Extends SchemaPin's ECDSA P-256 signing to cover file-based skill folders
 * (AgentSkills spec). Same keys, same .well-known discovery, new canonicalization
 * target.
 */

import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { readFileSync, readdirSync, writeFileSync, lstatSync, existsSync } from 'node:fs';
import { join, relative, basename, resolve } from 'node:path';
import { KeyManager, SignatureManager } from './crypto.js';
import { checkRevocationCombined } from './revocation.js';
import { ErrorCode } from './verification.js';

export const SIGNATURE_FILENAME = '.schemapin.sig';
const SCHEMAPIN_VERSION = '1.3';

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
 * @param {string} skillDir - Path to the skill folder
 * @param {string} privateKeyPem - PEM-encoded ECDSA P-256 private key
 * @param {string} domain - Signing domain (e.g. "thirdkey.ai")
 * @param {string|null} signerKid - Optional key ID (fingerprint). Auto-computed if null.
 * @param {string|null} skillName - Override for the skill name. Parsed from SKILL.md if not provided.
 * @returns {Object} The signature document that was written
 */
export function signSkill(skillDir, privateKeyPem, domain, signerKid = null, skillName = null) {
    const skillPath = resolve(skillDir);
    const privateKey = KeyManager.loadPrivateKeyPem(privateKeyPem);

    // Derive public key PEM from private key
    const privKeyObj = createPrivateKey(privateKeyPem);
    const pubKeyObj = createPublicKey(privKeyObj);
    const publicKeyPem = pubKeyObj.export({ type: 'spki', format: 'pem' });

    const { rootHash, manifest } = canonicalizeSkill(skillPath);

    if (skillName === null || skillName === undefined) {
        skillName = parseSkillName(skillPath);
    }

    if (signerKid === null || signerKid === undefined) {
        signerKid = KeyManager.calculateKeyFingerprint(publicKeyPem);
    }

    const signatureB64 = SignatureManager.signHash(rootHash, privateKey);

    const sigDoc = {
        schemapin_version: SCHEMAPIN_VERSION,
        skill_name: skillName,
        skill_hash: `sha256:${rootHash.toString('hex')}`,
        signature: signatureB64,
        signed_at: new Date().toISOString(),
        domain: domain,
        signer_kid: signerKid,
        file_manifest: manifest
    };

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

    return resultObj;
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
