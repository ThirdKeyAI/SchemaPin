/**
 * Offline and resolver-based schema verification for SchemaPin v1.2.
 */

import { SchemaPinCore } from './core.js';
import { KeyManager, SignatureManager } from './crypto.js';
import { checkRevocationCombined } from './revocation.js';
import { a2aAllows } from './a2a.js';

/**
 * Apply a signature `expires_at` check to a verification result (v1.4).
 *
 * Mirrors the Rust `VerificationResult::with_expiration_check` behaviour:
 *
 * - If `expiresAt` is null/undefined, the result is returned unchanged.
 * - If parseable and in the past, sets `expired = true`, copies `expiresAt`,
 *   and pushes a `'signature_expired'` warning. `valid` is left intact —
 *   expired signatures are *degraded*, not failed.
 * - If parseable and in the future, just records `expiresAt`.
 * - If unparseable, pushes a `'signature_expires_at_unparseable'` warning
 *   (fail-open) and does not mark expired.
 *
 * Mutates and returns the same `result` object for ergonomic chaining.
 *
 * @param {Object} result - VerificationResult-shaped object
 * @param {string|null|undefined} expiresAt - ISO 8601 / RFC 3339 timestamp
 * @returns {Object} The (possibly mutated) result
 */
export function applyExpirationCheck(result, expiresAt) {
    if (expiresAt === null || expiresAt === undefined) {
        return result;
    }
    if (!Array.isArray(result.warnings)) {
        result.warnings = [];
    }
    const ts = new Date(expiresAt);
    if (Number.isNaN(ts.getTime())) {
        result.warnings.push('signature_expires_at_unparseable');
        return result;
    }
    result.expires_at = expiresAt;
    if (ts.getTime() < Date.now()) {
        result.expired = true;
        result.warnings.push('signature_expired');
    }
    return result;
}

/**
 * Structured error codes for verification results.
 */
export const ErrorCode = Object.freeze({
    SIGNATURE_INVALID: 'signature_invalid',
    KEY_NOT_FOUND: 'key_not_found',
    KEY_REVOKED: 'key_revoked',
    KEY_PIN_MISMATCH: 'key_pin_mismatch',
    DISCOVERY_FETCH_FAILED: 'discovery_fetch_failed',
    DISCOVERY_INVALID: 'discovery_invalid',
    DOMAIN_MISMATCH: 'domain_mismatch',
    SCHEMA_CANONICALIZATION_FAILED: 'schema_canonicalization_failed',
    // v1.4 alpha.3: signature declared a canonicalization algorithm this
    // verifier does not support. Hard failure.
    CANONICALIZATION_UNSUPPORTED: 'canonicalization_unsupported',
    // v1.4 alpha.3: A2A scope violation (provider domain not in caller's
    // trusted_domains, or delegation_depth exceeded).
    A2A_SCOPE_VIOLATION: 'a2a_scope_violation',
    // v1.4 alpha.3 (bundle distribution): a trust bundle lacks the
    // bundle_authority / signature required to verify it.
    BUNDLE_UNSIGNED: 'bundle_unsigned',
    // v1.4 alpha.3 (bundle distribution): a trust bundle is past its
    // expires_at (or has an unparseable expires_at).
    BUNDLE_EXPIRED: 'bundle_expired'
});

/**
 * v1.4 alpha.3: canonicalization algorithm identifier.
 *
 * Signatures MAY carry a `canonicalization` field naming the algorithm used
 * to produce the signing input. Absence is equivalent to this identifier
 * for backward compatibility with v1.3 signatures. Verifiers MUST reject
 * any other value as `CANONICALIZATION_UNSUPPORTED`.
 */
export const CANONICALIZATION_V1 = 'schemapin-v1';

/**
 * Returns `null` when `algorithm` is supported, or the offending value
 * otherwise. The caller surfaces a non-null return as
 * `ErrorCode.CANONICALIZATION_UNSUPPORTED`.
 *
 * `null` / `undefined` are equivalent to the implicit `schemapin-v1`
 * default and are accepted (v1.3 backward compatibility).
 *
 * @param {string|null|undefined} algorithm
 * @returns {string|null}
 */
export function checkCanonicalization(algorithm) {
    if (algorithm === null || algorithm === undefined || algorithm === CANONICALIZATION_V1) {
        return null;
    }
    return algorithm;
}

/**
 * Lightweight in-memory fingerprint-based pin store.
 * Keys are stored by tool_id@domain.
 */
export class KeyPinStore {
    constructor() {
        this._pins = new Map();
    }

    _key(toolId, domain) {
        return `${toolId}@${domain}`;
    }

    /**
     * Check and optionally pin a key fingerprint.
     *
     * @param {string} toolId
     * @param {string} domain
     * @param {string} fingerprint
     * @returns {string} "first_use", "pinned", or "changed"
     */
    checkAndPin(toolId, domain, fingerprint) {
        const k = this._key(toolId, domain);
        const existing = this._pins.get(k);
        if (existing === undefined) {
            this._pins.set(k, fingerprint);
            return 'first_use';
        }
        if (existing === fingerprint) {
            return 'pinned';
        }
        return 'changed';
    }

    /**
     * Get the pinned fingerprint for a tool@domain.
     *
     * @param {string} toolId
     * @param {string} domain
     * @returns {string|null}
     */
    getPinned(toolId, domain) {
        return this._pins.get(this._key(toolId, domain)) ?? null;
    }

    /**
     * Serialize the pin store to JSON.
     *
     * @returns {string}
     */
    toJSON() {
        return JSON.stringify(Object.fromEntries(this._pins));
    }

    /**
     * Deserialize a pin store from JSON.
     *
     * @param {string} jsonStr
     * @returns {KeyPinStore}
     */
    static fromJSON(jsonStr) {
        const store = new KeyPinStore();
        const data = JSON.parse(jsonStr);
        for (const [key, value] of Object.entries(data)) {
            store._pins.set(key, value);
        }
        return store;
    }
}

/**
 * Verify a schema offline using pre-fetched discovery and revocation data.
 *
 * 7-step verification flow:
 * 1. Validate discovery document
 * 2. Extract public key and compute fingerprint
 * 3. Check revocation (both simple list + standalone doc)
 * 4. TOFU key pinning check
 * 5. Canonicalize schema and compute hash
 * 6. Verify ECDSA signature against hash
 * 7. Return structured result
 *
 * @param {Object} schema
 * @param {string} signatureB64
 * @param {string} domain
 * @param {string} toolId
 * @param {Object} discovery - Well-known response
 * @param {Object|null} revocation - Standalone revocation document
 * @param {KeyPinStore} pinStore
 * @param {string|null} [canonicalization] - v1.4 alpha.3 optional canonicalization
 *   algorithm identifier from the signature. `null` / `undefined` /
 *   `'schemapin-v1'` are equivalent and accepted; any other value fails with
 *   `CANONICALIZATION_UNSUPPORTED`.
 * @returns {Object} Verification result
 */
export function verifySchemaOffline(schema, signatureB64, domain, toolId, discovery, revocation, pinStore, canonicalization = null) {
    // Step 0 (v1.4 alpha.3): canonicalization algorithm check
    const unsupportedAlgo = checkCanonicalization(canonicalization);
    if (unsupportedAlgo !== null) {
        return {
            valid: false,
            domain,
            error_code: ErrorCode.CANONICALIZATION_UNSUPPORTED,
            error_message: `Unsupported canonicalization algorithm: ${unsupportedAlgo}`
        };
    }

    // Step 1: Validate discovery document
    const publicKeyPem = discovery?.public_key_pem;
    if (!publicKeyPem || !publicKeyPem.includes('-----BEGIN PUBLIC KEY-----')) {
        return {
            valid: false,
            domain,
            error_code: ErrorCode.DISCOVERY_INVALID,
            error_message: 'Discovery document missing or invalid public_key_pem'
        };
    }

    // Step 2: Extract public key and compute fingerprint
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

    // Step 3: Check revocation
    const simpleRevoked = discovery.revoked_keys || [];
    try {
        checkRevocationCombined(simpleRevoked, revocation, fingerprint);
    } catch (e) {
        return {
            valid: false,
            domain,
            error_code: ErrorCode.KEY_REVOKED,
            error_message: e.message
        };
    }

    // Step 4: TOFU key pinning
    const pinResult = pinStore.checkAndPin(toolId, domain, fingerprint);
    if (pinResult === 'changed') {
        return {
            valid: false,
            domain,
            error_code: ErrorCode.KEY_PIN_MISMATCH,
            error_message: 'Key fingerprint changed since last use'
        };
    }

    // Step 5: Canonicalize and hash
    let schemaHash;
    try {
        schemaHash = SchemaPinCore.canonicalizeAndHash(schema);
    } catch (e) {
        return {
            valid: false,
            domain,
            error_code: ErrorCode.SCHEMA_CANONICALIZATION_FAILED,
            error_message: `Failed to canonicalize schema: ${e.message}`
        };
    }

    // Step 6: Verify signature
    const valid = SignatureManager.verifySchemaSignature(schemaHash, signatureB64, publicKey);

    if (!valid) {
        return {
            valid: false,
            domain,
            error_code: ErrorCode.SIGNATURE_INVALID,
            error_message: 'Signature verification failed'
        };
    }

    // Step 7: Return success
    const result = {
        valid: true,
        domain,
        developer_name: discovery.developer_name || null,
        key_pinning: { status: pinResult },
        warnings: []
    };

    const schemaVersion = discovery.schema_version || '';
    if (schemaVersion && schemaVersion < '1.2') {
        result.warnings.push(
            `Discovery uses schema version ${schemaVersion}, consider upgrading to 1.2`
        );
    }

    return result;
}

/**
 * Verify a schema using a resolver for discovery and revocation.
 *
 * @param {Object} schema
 * @param {string} signatureB64
 * @param {string} domain
 * @param {string} toolId
 * @param {SchemaResolver} resolver
 * @param {KeyPinStore} pinStore
 * @returns {Promise<Object>} Verification result
 */
export async function verifySchemaWithResolver(schema, signatureB64, domain, toolId, resolver, pinStore) {
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

    return verifySchemaOffline(schema, signatureB64, domain, toolId, discovery, revocation, pinStore);
}

/**
 * Maximum A2A delegation depth allowed by this verifier (v1.4 alpha.3).
 *
 * Mirrors the AgentPin `max_delegation_depth` cap (AgentPin spec §4.3).
 * Bumping this on the SchemaPin side without a matching bump on AgentPin
 * would let SchemaPin accept chains AgentPin would reject — keep in lockstep.
 */
export const A2A_MAX_DELEGATION_DEPTH = 3;

/**
 * Verify a schema in the context of an A2A interaction (v1.4 alpha.3).
 *
 * Wraps {@link verifySchemaOffline} with an A2A scope check:
 *
 *   1. Reject when `context.delegationDepth > A2A_MAX_DELEGATION_DEPTH`.
 *      Surfaces as `A2A_SCOPE_VIOLATION`.
 *   2. Run the standard 7-step verification. If it fails, return that
 *      result unchanged.
 *   3. Reject when `context.trustedDomains` is non-empty and `domain` is
 *      not allowed by it. Surfaces as `A2A_SCOPE_VIOLATION`.
 *
 * On success the returned result is the result from step 2 unchanged — A2A
 * context does not modify the cryptographic outcome, only the policy
 * outcome.
 *
 * @param {Object} schema
 * @param {string} signatureB64
 * @param {string} domain
 * @param {string} toolId
 * @param {Object} discovery
 * @param {Object|null} revocation
 * @param {KeyPinStore} pinStore
 * @param {import('./a2a.js').A2aVerificationContext} context
 * @param {string|null} [canonicalization=null]
 * @returns {Object} Verification result
 */
export function verifySchemaForA2A(
    schema,
    signatureB64,
    domain,
    toolId,
    discovery,
    revocation,
    pinStore,
    context,
    canonicalization = null,
) {
    // Async import would force the public function to be async; instead use
    // a lazy require-style approach via dynamic await. Since a2a.js has no
    // side effects and tiny size, eager static import below is fine — JS
    // can't tree-shake conditionally either way.
    // (See bottom of file for the import.)
    if (context.delegationDepth > A2A_MAX_DELEGATION_DEPTH) {
        return {
            valid: false,
            domain,
            error_code: ErrorCode.A2A_SCOPE_VIOLATION,
            error_message:
                `A2A delegation_depth ${context.delegationDepth} exceeds cap of ${A2A_MAX_DELEGATION_DEPTH}`
        };
    }

    const result = verifySchemaOffline(
        schema,
        signatureB64,
        domain,
        toolId,
        discovery,
        revocation,
        pinStore,
        canonicalization,
    );
    if (!result.valid) {
        return result;
    }

    if (!a2aAllows(context.trustedDomains, domain)) {
        return {
            valid: false,
            domain,
            error_code: ErrorCode.A2A_SCOPE_VIOLATION,
            error_message: `Provider domain '${domain}' not in caller's A2A trusted_domains scope`
        };
    }

    return result;
}
