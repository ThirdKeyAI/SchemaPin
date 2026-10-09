/**
 * Skill folder signing and verification for SchemaPin v1.3 / v1.4.
 *
 * Extends SchemaPin's ECDSA P-256 signing to cover file-based skill folders
 * (AgentSkills spec). Same keys, same .well-known discovery, new canonicalization
 * target.
 *
 * ## Wire formats
 *
 * `schemapin_version: "1.4"` (the default for every new signature):
 *
 * - The directory is canonicalized with {@link canonicalizeSkill} (skill
 *   canonicalization v2, spec section 4b): every entry is hashed as
 *   `SHA-256("f" || be64(len(path)) || path || be64(len(content)) || content)`
 *   and the root hash is SHA-256 over `be64(len(path)) || path || digest` for
 *   every entry in code-point path order. Symlinks are rejected.
 * - `skill_hash` is `"sha256:" + hex(root_hash)`.
 * - The signature covers the **entire signature document**: the document is
 *   built with `signature: ""`, canonicalized with `schemapin-v1` and signed
 *   as `ECDSA-P256(SHA-256(canonical_bytes))`. `expires_at`, `schema_version`,
 *   `previous_hash`, `canonicalization`, `domain`, `skill_name`, `signer_kid`,
 *   `signed_at` and `file_manifest` are therefore all integrity-protected.
 *
 * `schemapin_version: "1.3"` (legacy, verify-only):
 *
 * - Entries hashed as `SHA-256(path || content)`, root hash SHA-256 of the
 *   concatenated hex digests, symlinks silently skipped, and the signature
 *   covers only the 32-byte root hash. None of the metadata fields are
 *   signed; verifiers surface a `legacy_signature_format` warning.
 *
 * Verification is fail-closed on expiration and on domain mismatch.
 */

import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { readFileSync, readdirSync, writeFileSync, lstatSync, existsSync } from 'node:fs';
import { join, relative, basename, resolve } from 'node:path';
import { SchemaPinCore, compareCodePoints } from './core.js';
import { KeyManager, SignatureManager } from './crypto.js';
import { InvalidDomainError, validateDomain } from './domain.js';
import { checkRevocationCombined, RevocationFetchError } from './revocation.js';
import { ErrorCode, EXPIRATION_SKEW_SECONDS, applyExpirationCheck, checkCanonicalization } from './verification.js';
import { verifyDnsMatch } from './dns.js';

export const SIGNATURE_FILENAME = '.schemapin.sig';
/** `schemapin_version` written on every new signature (signed-document format). */
export const SCHEMAPIN_VERSION = '1.4';
/** Legacy root-hash-only format; accepted on verification, never written. */
export const SCHEMAPIN_VERSION_LEGACY = '1.3';

/** Caps enforced by {@link canonicalizeSkill}. */
export const MAX_SKILL_FILES = 10000;
export const MAX_SKILL_TOTAL_BYTES = 256 * 1024 * 1024;

const REQUIRED_FIELDS = ['schemapin_version', 'skill_name', 'skill_hash', 'signature', 'signed_at', 'domain', 'signer_kid', 'file_manifest'];
const OPTIONAL_FIELDS = ['expires_at', 'schema_version', 'previous_hash', 'canonicalization'];

/**
 * Thrown when a skill directory cannot be canonicalized.
 */
export class SkillCanonicalizationError extends Error {
    constructor(message) {
        super(message);
        this.name = 'SkillCanonicalizationError';
    }
}

/**
 * Format a Date as RFC 3339 UTC with seconds precision and `Z` suffix.
 *
 * @param {Date} date
 * @returns {string} e.g. `2026-04-30T21:41:50Z`
 */
function toRfc3339Seconds(date) {
    const iso = date.toISOString(); // 2026-04-30T21:41:50.123Z
    return iso.replace(/\.\d{3}Z$/, 'Z');
}

function be64(n) {
    const buf = Buffer.alloc(8);
    buf.writeBigUInt64BE(BigInt(n));
    return buf;
}

function versionTuple(version) {
    if (typeof version !== 'string') {
        return null;
    }
    const m = /^(\d+)\.(\d+)$/.exec(version);
    return m ? [Number(m[1]), Number(m[2])] : null;
}

function isLegacyVersion(version) {
    const t = versionTuple(version);
    return t !== null && (t[0] < 1 || (t[0] === 1 && t[1] < 4));
}

/**
 * Recursive walk for skill canonicalization v2.
 *
 * @param {string} dir
 * @param {string} baseDir
 * @param {Array<[string, Buffer]>} entries
 * @param {{ total: number }} state
 */
function walkV2(dir, baseDir, entries, state) {
    const names = readdirSync(dir);
    for (const name of names) {
        const fullPath = join(dir, name);
        const stats = lstatSync(fullPath);
        if (stats.isSymbolicLink()) {
            throw new SkillCanonicalizationError(`symlink not permitted in skill directory: ${fullPath}`);
        }
        if (stats.isDirectory()) {
            walkV2(fullPath, baseDir, entries, state);
            continue;
        }
        if (!stats.isFile()) {
            throw new SkillCanonicalizationError(`non-regular file in skill directory: ${fullPath}`);
        }
        if (dir === baseDir && name === SIGNATURE_FILENAME) {
            continue;
        }
        const relPath = relative(baseDir, fullPath).split('\\').join('/');
        const pathBytes = Buffer.from(relPath, 'utf-8');
        if (pathBytes.toString('utf-8') !== relPath || relPath.includes('\uFFFD')) {
            throw new SkillCanonicalizationError(`path is not valid UTF-8: ${relPath}`);
        }
        const data = readFileSync(fullPath);
        state.total += data.length;
        if (entries.length + 1 > MAX_SKILL_FILES) {
            throw new SkillCanonicalizationError(`skill exceeds ${MAX_SKILL_FILES} files`);
        }
        if (state.total > MAX_SKILL_TOTAL_BYTES) {
            throw new SkillCanonicalizationError(`skill exceeds ${MAX_SKILL_TOTAL_BYTES} bytes`);
        }
        const digest = createHash('sha256')
            .update('f')
            .update(be64(pathBytes.length))
            .update(pathBytes)
            .update(be64(data.length))
            .update(data)
            .digest();
        entries.push([relPath, digest]);
    }
}

/**
 * Canonicalize a skill directory deterministically and compute the v2 root hash.
 *
 * Algorithm (spec section 4b):
 *   1. Walk the tree; directories are not entries. The top-level
 *      `.schemapin.sig` is excluded.
 *   2. Any symlink (file or directory) or non-regular file aborts
 *      canonicalization -- unsigned content must not be reachable from a
 *      signed skill.
 *   3. Paths are relative, forward-slash separated, UTF-8, sorted by code point.
 *   4. Per entry: `SHA-256(0x66 || be64(len(path)) || path || be64(len(content)) || content)`.
 *   5. Root: SHA-256 over `be64(len(path)) || path || entry_digest` for every
 *      entry in sorted order.
 *
 * @param {string} skillDir - Path to skill directory
 * @returns {{ rootHash: Buffer, manifest: Object }} Root hash and file manifest
 * @throws {SkillCanonicalizationError}
 */
export function canonicalizeSkill(skillDir) {
    const skillPath = resolve(skillDir);
    const entries = [];
    walkV2(skillPath, skillPath, entries, { total: 0 });

    if (entries.length === 0) {
        throw new SkillCanonicalizationError(`Skill directory is empty or contains no signable files: ${skillDir}`);
    }
    entries.sort((a, b) => compareCodePoints(a[0], b[0]));

    const root = createHash('sha256');
    const manifest = {};
    for (const [relPath, digest] of entries) {
        const pathBytes = Buffer.from(relPath, 'utf-8');
        root.update(be64(pathBytes.length)).update(pathBytes).update(digest);
        manifest[relPath] = `sha256:${digest.toString('hex')}`;
    }
    return { rootHash: root.digest(), manifest };
}

/**
 * Legacy (`schemapin_version: "1.3"`) walk: files first, then directories,
 * symlinks and `.schemapin.sig` skipped at any depth.
 */
function walkV1(dir, baseDir, manifest) {
    const entries = readdirSync(dir, { withFileTypes: true });
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

    for (const fname of files) {
        if (fname === SIGNATURE_FILENAME) {
            continue;
        }
        const fullPath = join(dir, fname);
        if (lstatSync(fullPath).isSymbolicLink()) {
            continue;
        }
        const relPath = relative(baseDir, fullPath).split('\\').join('/');
        const digest = createHash('sha256')
            .update(Buffer.from(relPath, 'utf-8'))
            .update(readFileSync(fullPath))
            .digest('hex');
        manifest[relPath] = `sha256:${digest}`;
    }

    for (const dname of dirs) {
        const subdir = join(dir, dname);
        if (lstatSync(subdir).isSymbolicLink()) {
            continue;
        }
        walkV1(subdir, baseDir, manifest);
    }
}

/**
 * Legacy (`schemapin_version: "1.3"`) skill canonicalization.
 *
 * Kept only so that pre-1.4 signatures still verify. Per-file digest is
 * `SHA-256(path || content)`, the root hash is SHA-256 of the concatenated
 * hex digests, symlinks are skipped and `.schemapin.sig` is excluded at any
 * depth. Do not use for new signatures.
 *
 * @param {string} skillDir
 * @returns {{ rootHash: Buffer, manifest: Object }}
 */
export function canonicalizeSkillV1(skillDir) {
    const skillPath = resolve(skillDir);
    const manifest = {};
    walkV1(skillPath, skillPath, manifest);
    if (Object.keys(manifest).length === 0) {
        throw new SkillCanonicalizationError(`Skill directory is empty or contains no signable files: ${skillDir}`);
    }
    const sortedKeys = Object.keys(manifest).sort(compareCodePoints);
    const sortedDigests = sortedKeys.map(k => manifest[k].slice('sha256:'.length));
    const rootHash = createHash('sha256').update(sortedDigests.join(''), 'utf-8').digest();
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
 * @throws {Error} If .schemapin.sig does not exist or is not a JSON object
 */
export function loadSignature(skillDir) {
    const sigPath = join(resolve(skillDir), SIGNATURE_FILENAME);
    if (!existsSync(sigPath)) {
        throw new Error(`Signature file not found: ${sigPath}`);
    }
    const text = readFileSync(sigPath, 'utf-8');
    const data = JSON.parse(text);
    if (data === null || typeof data !== 'object' || Array.isArray(data)) {
        throw new Error('.schemapin.sig must contain a JSON object');
    }
    return data;
}

/**
 * Build the canonical bytes a v1.4 signature covers.
 *
 * Takes the known signature fields (unknown fields are ignored and therefore
 * unprotected), drops absent / empty optional fields, forces `signature` to
 * `""` and canonicalizes with `schemapin-v1`.
 *
 * @param {Object} signatureData
 * @returns {Buffer}
 * @throws {Error} if a required field is missing or has the wrong type
 */
export function signingInput(signatureData) {
    const doc = {};
    for (const key of REQUIRED_FIELDS) {
        if (key === 'signature') {
            continue;
        }
        const value = signatureData[key];
        if (key === 'file_manifest') {
            if (value === null || typeof value !== 'object' || Array.isArray(value)) {
                throw new Error('file_manifest must be an object');
            }
        } else if (typeof value !== 'string') {
            throw new Error(`signature document field ${JSON.stringify(key)} is missing`);
        }
        doc[key] = value;
    }
    for (const key of OPTIONAL_FIELDS) {
        const value = signatureData[key];
        if (value === null || value === undefined || value === '') {
            continue;
        }
        if (typeof value !== 'string') {
            throw new Error(`signature document field ${JSON.stringify(key)} must be a string`);
        }
        doc[key] = value;
    }
    doc.signature = '';
    return Buffer.from(SchemaPinCore.canonicalizeSchema(doc), 'utf-8');
}

/**
 * Canonicalize a skill directory, sign, and write .schemapin.sig.
 *
 * Thin wrapper over {@link signSkillWithOptions}.
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
 * Chain check error.
 *
 * Subclass of Error. Distinguish via the `kind` property:
 *   - `'no_previous_hash'` — current signature has no `previous_hash` field
 *   - `'mismatch'` — current.previous_hash !== previous.skill_hash
 *   - `'legacy'` — one of the documents is a legacy 1.3 signature whose
 *     `skill_hash` is not covered by its signature
 */
export class ChainError extends Error {
    /**
     * @param {string} kind - 'no_previous_hash' | 'mismatch' | 'legacy'
     * @param {string} message
     */
    constructor(kind, message) {
        super(message);
        this.name = 'ChainError';
        this.kind = kind;
    }
}

/**
 * Verify that `current` is the legitimate successor of `previous` via the
 * `previous_hash` lineage chain.
 *
 * Checks `current.previous_hash === previous.skill_hash`.
 *
 * This is a pure-metadata check — no cryptography is re-evaluated. Both
 * signatures must already be cryptographically verified separately via
 * {@link verifySkillOffline}, and both must be `schemapin_version >= "1.4"`
 * documents so that `skill_hash` / `previous_hash` are covered by their
 * signatures (legacy 1.3 documents are rejected).
 *
 * @param {Object} current - The new signature dict (must have `previous_hash`)
 * @param {Object} previous - The prior signature dict (must have `skill_hash`)
 * @throws {ChainError}
 */
export function verifyChain(current, previous) {
    for (const [label, doc] of [['current', current], ['previous', previous]]) {
        if (isLegacyVersion(doc.schemapin_version)) {
            throw new ChainError('legacy', `${label} signature is a legacy 1.3 document; its skill_hash is unsigned`);
        }
    }
    const claimed = current.previous_hash;
    if (claimed === null || claimed === undefined) {
        throw new ChainError(
            'no_previous_hash',
            'current signature has no previous_hash field'
        );
    }
    const expected = previous.skill_hash;
    if (claimed !== expected) {
        throw new ChainError(
            'mismatch',
            `previous_hash mismatch: current.previous_hash = ${claimed}, previous.skill_hash = ${expected}`
        );
    }
}

/**
 * Canonicalize a skill directory, sign, and write a v1.4 signature document.
 *
 * The whole document (including `expires_at` when `options.expiresIn` is
 * set, written as RFC 3339 `Z` with second precision) is covered by the
 * signature. See the module docs.
 *
 * Options:
 *   - `signerKid` - Override the signer key id (KID). Defaults to the
 *     discovery fingerprint of the public key.
 *   - `skillName` - Override the skill name. Defaults to the SKILL.md
 *     frontmatter `name:` or directory basename.
 *   - `expiresIn` - Time-to-live for the signature, in milliseconds.
 *   - `schemaVersion` - semver string identifying this version of the artifact.
 *   - `previousHash` - `sha256:<hex>` of the prior version's `skill_hash`.
 *   - `canonicalization` - algorithm identifier (`'schemapin-v1'`).
 *
 * @param {string} skillDir - Path to the skill folder
 * @param {string} privateKeyPem - PEM-encoded ECDSA P-256 private key
 * @param {string} domain - Signing domain
 * @param {{ signerKid?: string|null, skillName?: string|null, expiresIn?: number|null, schemaVersion?: string|null, previousHash?: string|null, canonicalization?: string|null }} [options]
 * @returns {Object} The signature document that was written
 * @throws {InvalidDomainError|SkillCanonicalizationError}
 */
export function signSkillWithOptions(skillDir, privateKeyPem, domain, options = {}) {
    const {
        signerKid: optSignerKid = null,
        skillName: optSkillName = null,
        expiresIn = null,
        schemaVersion = null,
        previousHash = null,
        canonicalization = null
    } = options;

    const skillPath = resolve(skillDir);
    domain = validateDomain(domain);
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

    const now = new Date();
    let expiresAt = null;
    if (expiresIn !== null && expiresIn !== undefined) {
        expiresAt = toRfc3339Seconds(new Date(now.getTime() + expiresIn));
    }

    const ordered = {
        schemapin_version: SCHEMAPIN_VERSION,
        skill_name: skillName,
        skill_hash: `sha256:${rootHash.toString('hex')}`,
        signature: '',
        signed_at: toRfc3339Seconds(now)
    };
    if (expiresAt !== null) {
        ordered.expires_at = expiresAt;
    }
    if (schemaVersion !== null && schemaVersion !== undefined) {
        ordered.schema_version = schemaVersion;
    }
    if (previousHash !== null && previousHash !== undefined) {
        ordered.previous_hash = previousHash;
    }
    if (canonicalization !== null && canonicalization !== undefined) {
        ordered.canonicalization = canonicalization;
    }
    ordered.domain = domain;
    ordered.signer_kid = signerKid;
    ordered.file_manifest = manifest;

    ordered.signature = SignatureManager.signHash(signingInput(ordered), privateKey);

    const sigPath = join(skillPath, SIGNATURE_FILENAME);
    writeFileSync(sigPath, JSON.stringify(ordered, null, 2) + '\n', 'utf-8');
    return ordered;
}

function failure(domain, code, message) {
    return { valid: false, domain, error_code: code, error_message: message };
}

/**
 * Verify a signed skill folder offline.
 *
 * Steps:
 *   1. Load or accept signature data; check `canonicalization`
 *   2. Bind the domain: when `expectedDomain` is given it must equal the
 *      signature's `domain` (`DOMAIN_MISMATCH` otherwise). Pass it whenever
 *      you know which domain the discovery document belongs to -- the
 *      signature's own `domain` field is display-only.
 *   3. Validate discovery document, load key, compute fingerprint
 *   4. Check revocation
 *   5. TOFU pin check (read-only)
 *   6. Recompute the root hash, require `skill_hash` to match, verify the
 *      signature (over the whole document for 1.4, over the root hash for
 *      legacy 1.3)
 *   7. Expiration check (fail-closed unless `allowExpired`)
 *   8. Pin on first use, return the result with lineage metadata
 *
 * @param {string} skillDir - Path to skill directory
 * @param {Object} discovery - Well-known discovery document
 * @param {Object|null} signatureData - Pre-loaded signature data (loads from file if null)
 * @param {Object|null} revocationDoc - Standalone revocation document
 * @param {KeyPinStore|null} pinStore - TOFU pin store
 * @param {string|null} toolId - Tool identifier for pinning
 * @param {string|null} [expectedDomain=null] - Domain to bind the skill to
 * @param {boolean} [allowExpired=false] - Accept expired signatures (degraded)
 * @returns {Object} Verification result
 */
export function verifySkillOffline(skillDir, discovery, signatureData = null, revocationDoc = null, pinStore = null, toolId = null, expectedDomain = null, allowExpired = false) {
    const skillPath = resolve(skillDir);

    // Step 1: Load signature data
    if (signatureData === null || signatureData === undefined) {
        try {
            signatureData = loadSignature(skillPath);
        } catch (e) {
            return {
                valid: false,
                error_code: ErrorCode.SIGNATURE_INVALID,
                error_message: `No usable .schemapin.sig found in skill directory: ${e.message}`
            };
        }
    }

    const sigDomain = signatureData.domain;
    if (toolId === null || toolId === undefined) {
        toolId = signatureData.skill_name || basename(skillPath);
    }

    const unsupportedAlgo = checkCanonicalization(signatureData.canonicalization);
    if (unsupportedAlgo !== null) {
        return failure(expectedDomain, ErrorCode.CANONICALIZATION_UNSUPPORTED, `Unsupported canonicalization algorithm: ${unsupportedAlgo}`);
    }

    // Step 2: Domain binding
    const warnings = [];
    let domain;
    if (expectedDomain !== null && expectedDomain !== undefined) {
        try {
            domain = validateDomain(expectedDomain);
        } catch (e) {
            if (e instanceof InvalidDomainError) {
                return failure(expectedDomain, ErrorCode.DOMAIN_INVALID, e.message);
            }
            throw e;
        }
        if (typeof sigDomain !== 'string' || sigDomain.toLowerCase() !== domain) {
            return failure(domain, ErrorCode.DOMAIN_MISMATCH,
                `signature domain ${JSON.stringify(sigDomain)} does not match expected domain ${JSON.stringify(domain)}`);
        }
    } else {
        try {
            domain = validateDomain(typeof sigDomain === 'string' ? sigDomain : '');
        } catch (e) {
            if (e instanceof InvalidDomainError) {
                return { valid: false, error_code: ErrorCode.DOMAIN_INVALID, error_message: `signature domain is invalid: ${e.message}` };
            }
            throw e;
        }
        warnings.push('domain_unbound');
    }

    // Step 3: Validate discovery document
    const publicKeyPem = discovery?.public_key_pem;
    if (!publicKeyPem || !publicKeyPem.includes('-----BEGIN PUBLIC KEY-----')) {
        return failure(domain, ErrorCode.DISCOVERY_INVALID, 'Discovery document missing or invalid public_key_pem');
    }

    let publicKey, fingerprint;
    try {
        publicKey = KeyManager.loadPublicKeyPem(publicKeyPem);
        fingerprint = KeyManager.calculateKeyFingerprint(publicKeyPem);
    } catch (e) {
        return failure(domain, ErrorCode.KEY_NOT_FOUND, `Failed to load public key: ${e.message}`);
    }

    // Step 4: Check revocation
    const simpleRevoked = discovery.revoked_keys || [];
    try {
        checkRevocationCombined(simpleRevoked, revocationDoc, fingerprint);
    } catch (e) {
        return failure(domain, ErrorCode.KEY_REVOKED, e.message);
    }

    // Step 5: TOFU pin check (read-only until the signature verifies)
    let pinResult = null;
    if (pinStore !== null && pinStore !== undefined) {
        pinResult = pinStore.check(toolId, domain, fingerprint);
        if (pinResult === 'changed') {
            return failure(domain, ErrorCode.KEY_PIN_MISMATCH, 'Key fingerprint changed since last use');
        }
    }

    // Step 6: Canonicalize and verify
    const version = signatureData.schemapin_version;
    if (versionTuple(version) === null) {
        return failure(domain, ErrorCode.SIGNATURE_INVALID, `unsupported schemapin_version ${JSON.stringify(version)}`);
    }
    const legacy = isLegacyVersion(version);
    let rootHash;
    try {
        rootHash = (legacy ? canonicalizeSkillV1(skillPath) : canonicalizeSkill(skillPath)).rootHash;
    } catch (e) {
        return failure(domain, ErrorCode.SCHEMA_CANONICALIZATION_FAILED, `Failed to canonicalize skill: ${e.message}`);
    }

    const signatureB64 = signatureData.signature || '';
    let valid;
    if (legacy) {
        valid = SignatureManager.verifySignature(rootHash, signatureB64, publicKey);
        warnings.push('legacy_signature_format');
    } else {
        const expectedHash = `sha256:${rootHash.toString('hex')}`;
        if (signatureData.skill_hash !== expectedHash) {
            return failure(domain, ErrorCode.SIGNATURE_INVALID, 'skill_hash does not match the directory contents');
        }
        let input;
        try {
            input = signingInput(signatureData);
        } catch (e) {
            return failure(domain, ErrorCode.SIGNATURE_INVALID, `malformed signature document: ${e.message}`);
        }
        valid = SignatureManager.verifySignature(input, signatureB64, publicKey);
    }

    if (!valid) {
        return failure(domain, ErrorCode.SIGNATURE_INVALID, 'Signature verification failed');
    }

    // Step 7: Expiration (fail-closed by default)
    const resultObj = {
        valid: true,
        domain,
        developer_name: discovery.developer_name || null,
        key_pinning: null,
        warnings
    };
    applyExpirationCheck(resultObj, signatureData.expires_at ?? null, allowExpired, EXPIRATION_SKEW_SECONDS);
    if (!resultObj.valid) {
        return resultObj;
    }

    // Step 8: Pin only now, then surface lineage metadata
    if (pinStore !== null && pinStore !== undefined && pinResult === 'first_use') {
        pinStore.pin(toolId, domain, fingerprint);
    }
    if (pinResult !== null) {
        resultObj.key_pinning = { status: pinResult };
    }
    if (signatureData.schema_version !== null && signatureData.schema_version !== undefined) {
        resultObj.schema_version = signatureData.schema_version;
    }
    if (signatureData.previous_hash !== null && signatureData.previous_hash !== undefined) {
        resultObj.previous_hash = signatureData.previous_hash;
    }

    return resultObj;
}

/**
 * Verify a signed skill folder offline with an optional DNS TXT cross-check (v1.4).
 *
 * Behaves identically to {@link verifySkillOffline}, with a DNS TXT
 * fingerprint cross-check performed first when `dnsTxt` is non-null. A
 * mismatch is a hard `DOMAIN_MISMATCH` failure and nothing is pinned.
 *
 * @param {string} skillDir - Path to skill directory
 * @param {Object} discovery - Well-known discovery document
 * @param {Object|null} signatureData - Pre-loaded signature data (loads from file if null)
 * @param {Object|null} revocationDoc - Standalone revocation document
 * @param {KeyPinStore|null} pinStore - TOFU pin store
 * @param {string|null} toolId - Tool identifier for pinning
 * @param {Object|null} dnsTxt - Parsed DNS TXT record (`{ version, kid, fingerprint }`)
 * @param {string|null} [expectedDomain=null]
 * @param {boolean} [allowExpired=false]
 * @returns {Object} Verification result
 */
export function verifySkillOfflineWithDns(skillDir, discovery, signatureData = null, revocationDoc = null, pinStore = null, toolId = null, dnsTxt = null, expectedDomain = null, allowExpired = false) {
    if (dnsTxt !== null && dnsTxt !== undefined) {
        try {
            verifyDnsMatch(discovery, dnsTxt);
        } catch (e) {
            return failure(expectedDomain, ErrorCode.DOMAIN_MISMATCH, e.message);
        }
    }
    return verifySkillOffline(skillDir, discovery, signatureData, revocationDoc, pinStore, toolId, expectedDomain, allowExpired);
}

/**
 * Verify a signed skill folder using a resolver for discovery.
 *
 * The signature's `domain` must equal `domain` (checked before any network
 * I/O); the discovery document is fetched for `domain` and the pin is keyed
 * by it. Revocation is fail-closed unless `allowUnreachableRevocation`.
 *
 * @param {string} skillDir - Path to skill directory
 * @param {string} domain - Domain to resolve discovery for and bind the skill to
 * @param {Object} resolver - SchemaResolver instance
 * @param {KeyPinStore|null} pinStore - TOFU pin store
 * @param {string|null} toolId - Tool identifier for pinning
 * @param {boolean} [allowExpired=false]
 * @param {boolean} [allowUnreachableRevocation=false]
 * @returns {Promise<Object>} Verification result
 */
export async function verifySkillWithResolver(skillDir, domain, resolver, pinStore = null, toolId = null, allowExpired = false, allowUnreachableRevocation = false) {
    try {
        domain = validateDomain(domain);
    } catch (e) {
        if (e instanceof InvalidDomainError) {
            return failure(domain, ErrorCode.DOMAIN_INVALID, e.message);
        }
        throw e;
    }

    let signatureData;
    try {
        signatureData = loadSignature(skillDir);
    } catch (e) {
        return failure(domain, ErrorCode.SIGNATURE_INVALID, `No usable .schemapin.sig found in skill directory: ${e.message}`);
    }
    const sigDomain = signatureData.domain;
    if (typeof sigDomain !== 'string' || sigDomain.toLowerCase() !== domain) {
        return failure(domain, ErrorCode.DOMAIN_MISMATCH,
            `signature domain ${JSON.stringify(sigDomain)} does not match expected domain ${JSON.stringify(domain)}`);
    }

    const discovery = await resolver.resolveDiscovery(domain);
    if (!discovery) {
        return failure(domain, ErrorCode.DISCOVERY_FETCH_FAILED, `Could not resolve discovery for domain: ${domain}`);
    }

    let revocation;
    try {
        revocation = await resolver.resolveRevocation(domain, discovery);
    } catch (e) {
        if (!(e instanceof RevocationFetchError)) {
            throw e;
        }
        if (!allowUnreachableRevocation) {
            return failure(domain, ErrorCode.DISCOVERY_FETCH_FAILED, `Revocation document unreachable (fail-closed): ${e.message}`);
        }
        revocation = null;
    }

    return verifySkillOffline(skillDir, discovery, signatureData, revocation, pinStore, toolId, domain, allowExpired);
}

/**
 * Compare current file manifest against the signed manifest.
 *
 * Only meaningful for `schemapin_version >= "1.4"` documents, whose
 * `file_manifest` is covered by the signature; for legacy 1.3 documents the
 * manifest is unsigned and this is a diagnostic aid only.
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
