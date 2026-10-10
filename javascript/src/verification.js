/**
 * Offline and resolver-based schema verification for SchemaPin v1.2.
 */

import { SchemaPinCore } from './core.js';
import { KeyManager, SignatureManager } from './crypto.js';
import { checkRevocationCombined, RevocationFetchError } from './revocation.js';
import { a2aAllows } from './a2a.js';
import { verifyDnsMatch } from './dns.js';
import { InvalidDomainError, validateDomain } from './domain.js';

/** Clock-skew tolerance applied to `expires_at` comparisons (seconds). */
export const EXPIRATION_SKEW_SECONDS = 300;

const RFC3339_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;

/**
 * Parse a strict RFC 3339 timestamp (`T` separator, mandatory offset).
 *
 * `new Date(string)` accepts date-only and local-time strings that the other
 * SDKs reject; this helper only accepts `YYYY-MM-DDTHH:MM:SS[.frac](Z|±HH:MM)`.
 *
 * @param {*} value
 * @returns {number|null} milliseconds since the epoch, or null when invalid
 */
export function parseRfc3339(value) {
    if (typeof value !== 'string' || !RFC3339_RE.test(value)) {
        return null;
    }
    const ms = Date.parse(value);
    return Number.isNaN(ms) ? null : ms;
}

/**
 * Apply a signature `expires_at` check to a verification result (v1.4).
 *
 * Expiration is **fail-closed** by default:
 *
 * - `expiresAt` of null/undefined leaves the result unchanged.
 * - A value that is not strict RFC 3339 fails with `SIGNATURE_EXPIRED`
 *   (`allowExpired` downgrades this to a `signature_expires_at_unparseable`
 *   warning).
 * - A timestamp more than `skewSeconds` in the past fails with
 *   `SIGNATURE_EXPIRED` and sets `expired = true`. With `allowExpired` the
 *   result stays valid but is marked `expired` and carries a
 *   `signature_expired` warning (the pre-1.4.0 "degraded" behavior).
 * - A future timestamp just records `expires_at`.
 *
 * Mutates and returns the same `result` object for ergonomic chaining.
 *
 * @param {Object} result - VerificationResult-shaped object
 * @param {string|null|undefined} expiresAt - RFC 3339 timestamp
 * @param {boolean} [allowExpired=false]
 * @param {number} [skewSeconds=EXPIRATION_SKEW_SECONDS]
 * @returns {Object} The (possibly mutated) result
 */
export function applyExpirationCheck(result, expiresAt, allowExpired = false, skewSeconds = EXPIRATION_SKEW_SECONDS) {
    if (expiresAt === null || expiresAt === undefined) {
        return result;
    }
    if (!Array.isArray(result.warnings)) {
        result.warnings = [];
    }
    const ms = parseRfc3339(expiresAt);
    if (ms === null) {
        if (allowExpired) {
            result.warnings.push('signature_expires_at_unparseable');
            return result;
        }
        result.valid = false;
        result.error_code = ErrorCode.SIGNATURE_EXPIRED;
        result.error_message = `expires_at is not a valid RFC 3339 timestamp: ${JSON.stringify(expiresAt)}`;
        return result;
    }
    result.expires_at = expiresAt;
    if (Date.now() > ms + skewSeconds * 1000) {
        result.expired = true;
        if (allowExpired) {
            result.warnings.push('signature_expired');
        } else {
            result.valid = false;
            result.error_code = ErrorCode.SIGNATURE_EXPIRED;
            result.error_message = `signature expired at ${expiresAt}`;
        }
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
    BUNDLE_EXPIRED: 'bundle_expired',
    // A signature's expires_at is in the past (or unparseable) and the
    // caller did not opt in with allowExpired. Hard failure.
    SIGNATURE_EXPIRED: 'signature_expired',
    // The caller-supplied domain is not a valid RFC 1123 hostname.
    DOMAIN_INVALID: 'domain_invalid',
    // A trust bundle's authority key is not pre-seeded in the authority store
    // and the caller did not opt in to first-use trust.
    BUNDLE_AUTHORITY_UNTRUSTED: 'bundle_authority_untrusted'
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
 *
 * Keys are stored by tool_id@domain. Verification flows use {@link check}
 * before the signature check and {@link pin} only after it succeeds, so a
 * failed verification never leaves a pin behind. Operators can pre-seed
 * expected fingerprints with {@link seed}.
 */
export class KeyPinStore {
    constructor() {
        this._pins = new Map();
    }

    _key(toolId, domain) {
        return `${toolId}@${domain}`;
    }

    /**
     * Compare `fingerprint` with the pinned value without mutating.
     *
     * @param {string} toolId
     * @param {string} domain
     * @param {string} fingerprint
     * @returns {string} "first_use", "pinned", or "changed"
     */
    check(toolId, domain, fingerprint) {
        const existing = this._pins.get(this._key(toolId, domain));
        if (existing === undefined) {
            return 'first_use';
        }
        return existing === fingerprint ? 'pinned' : 'changed';
    }

    /**
     * Pin `fingerprint` for tool@domain (overwrites).
     *
     * @param {string} toolId
     * @param {string} domain
     * @param {string} fingerprint
     */
    pin(toolId, domain, fingerprint) {
        this._pins.set(this._key(toolId, domain), fingerprint);
    }

    /**
     * Pre-seed an expected fingerprint (out-of-band trust establishment).
     *
     * @param {string} toolId
     * @param {string} domain
     * @param {string} fingerprint
     */
    seed(toolId, domain, fingerprint) {
        this.pin(toolId, domain, fingerprint);
    }

    /**
     * Check and pin on first use in one step. Prefer `check` + `pin` so that
     * pinning can be deferred until after signature verification.
     *
     * @param {string} toolId
     * @param {string} domain
     * @param {string} fingerprint
     * @returns {string} "first_use", "pinned", or "changed"
     */
    checkAndPin(toolId, domain, fingerprint) {
        const result = this.check(toolId, domain, fingerprint);
        if (result === 'first_use') {
            this.pin(toolId, domain, fingerprint);
        }
        return result;
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
        if (data === null || typeof data !== 'object' || Array.isArray(data)) {
            throw new Error('pin store JSON must be an object of string fingerprints');
        }
        for (const [key, value] of Object.entries(data)) {
            if (typeof value !== 'string') {
                throw new Error('pin store JSON must be an object of string fingerprints');
            }
            store._pins.set(key, value);
        }
        return store;
    }
}

/**
 * Verify a schema offline using pre-fetched discovery and revocation data.
 *
 * Verification flow:
 * 1. Validate the canonicalization identifier and the domain syntax
 * 2. Validate discovery document
 * 3. Extract public key and compute fingerprint
 * 4. Check revocation (both simple list + standalone doc)
 * 5. TOFU pin check (read-only)
 * 6. Canonicalize schema, compute hash, verify ECDSA signature
 * 7. Pin the key on first use (only after a successful verification)
 * 8. Return structured result
 *
 * @param {Object} schema
 * @param {string} signatureB64
 * @param {string} domain
 * @param {string} toolId
 * @param {Object} discovery - Well-known response
 * @param {Object|null} revocation - Standalone revocation document
 * @param {KeyPinStore} pinStore
 * @param {string|null} [canonicalization] - v1.4 optional canonicalization
 *   algorithm identifier from the signature. `null` / `undefined` /
 *   `'schemapin-v1'` are equivalent and accepted; any other value fails with
 *   `CANONICALIZATION_UNSUPPORTED`.
 * @returns {Object} Verification result
 */
export function verifySchemaOffline(schema, signatureB64, domain, toolId, discovery, revocation, pinStore, canonicalization = null) {
    // Step 1: canonicalization algorithm + domain syntax
    const unsupportedAlgo = checkCanonicalization(canonicalization);
    if (unsupportedAlgo !== null) {
        return {
            valid: false,
            domain,
            error_code: ErrorCode.CANONICALIZATION_UNSUPPORTED,
            error_message: `Unsupported canonicalization algorithm: ${unsupportedAlgo}`
        };
    }
    try {
        domain = validateDomain(domain);
    } catch (e) {
        if (e instanceof InvalidDomainError) {
            return { valid: false, domain, error_code: ErrorCode.DOMAIN_INVALID, error_message: e.message };
        }
        throw e;
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
        checkRevocationCombined(simpleRevoked, revocation, fingerprint);
    } catch (e) {
        return {
            valid: false,
            domain,
            error_code: ErrorCode.KEY_REVOKED,
            error_message: e.message
        };
    }

    // Step 5: TOFU pin check (no write yet)
    const pinResult = pinStore.check(toolId, domain, fingerprint);
    if (pinResult === 'changed') {
        return {
            valid: false,
            domain,
            error_code: ErrorCode.KEY_PIN_MISMATCH,
            error_message: 'Key fingerprint changed since last use'
        };
    }

    // Step 6: Canonicalize, hash, verify
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

    const valid = SignatureManager.verifySchemaSignature(schemaHash, signatureB64, publicKey);

    if (!valid) {
        return {
            valid: false,
            domain,
            error_code: ErrorCode.SIGNATURE_INVALID,
            error_message: 'Signature verification failed'
        };
    }

    // Step 7: Pin only after the signature verified
    if (pinResult === 'first_use') {
        pinStore.pin(toolId, domain, fingerprint);
    }

    // Step 8: Return success
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
 * {@link verifySchemaOffline} plus a DNS TXT second-channel check.
 *
 * When `dnsTxt` is given (see `fetchDnsTxt`), the discovery key's
 * fingerprint must match the TXT record or the result is a hard
 * `DOMAIN_MISMATCH` failure. The DNS check runs before anything is pinned.
 *
 * @param {Object} schema
 * @param {string} signatureB64
 * @param {string} domain
 * @param {string} toolId
 * @param {Object} discovery
 * @param {Object|null} revocation
 * @param {KeyPinStore} pinStore
 * @param {Object|null} dnsTxt - Parsed DNS TXT record (`{ version, kid, fingerprint }`)
 * @param {string|null} [canonicalization=null]
 * @returns {Object} Verification result
 */
export function verifySchemaOfflineWithDns(schema, signatureB64, domain, toolId, discovery, revocation, pinStore, dnsTxt, canonicalization = null) {
    if (dnsTxt !== null && dnsTxt !== undefined) {
        try {
            verifyDnsMatch(discovery, dnsTxt);
        } catch (e) {
            return { valid: false, domain, error_code: ErrorCode.DOMAIN_MISMATCH, error_message: e.message };
        }
    }
    return verifySchemaOffline(schema, signatureB64, domain, toolId, discovery, revocation, pinStore, canonicalization);
}

/**
 * Verify a schema using a resolver for discovery and revocation.
 *
 * Revocation is fail-closed: if the discovery document declares a
 * `revocation_endpoint` that cannot be fetched, verification fails with
 * `DISCOVERY_FETCH_FAILED` unless `allowUnreachableRevocation` is true.
 *
 * @param {Object} schema
 * @param {string} signatureB64
 * @param {string} domain
 * @param {string} toolId
 * @param {SchemaResolver} resolver
 * @param {KeyPinStore} pinStore
 * @param {boolean} [allowUnreachableRevocation=false]
 * @returns {Promise<Object>} Verification result
 */
export async function verifySchemaWithResolver(schema, signatureB64, domain, toolId, resolver, pinStore, allowUnreachableRevocation = false) {
    try {
        domain = validateDomain(domain);
    } catch (e) {
        if (e instanceof InvalidDomainError) {
            return { valid: false, domain, error_code: ErrorCode.DOMAIN_INVALID, error_message: e.message };
        }
        throw e;
    }

    const discovery = await resolver.resolveDiscovery(domain);
    if (!discovery) {
        return {
            valid: false,
            domain,
            error_code: ErrorCode.DISCOVERY_FETCH_FAILED,
            error_message: `Could not resolve discovery for domain: ${domain}`
        };
    }

    let revocation;
    try {
        revocation = await resolver.resolveRevocation(domain, discovery);
    } catch (e) {
        if (!(e instanceof RevocationFetchError)) {
            throw e;
        }
        if (!allowUnreachableRevocation) {
            return {
                valid: false,
                domain,
                error_code: ErrorCode.DISCOVERY_FETCH_FAILED,
                error_message: `Revocation document unreachable (fail-closed): ${e.message}`
            };
        }
        revocation = null;
    }

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
