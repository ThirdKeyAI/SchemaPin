/**
 * Offline and resolver-based schema verification for SchemaPin v1.2.
 */

import { SchemaPinCore } from './core.js';
import { KeyManager, SignatureManager } from './crypto.js';
import { checkRevocationCombined } from './revocation.js';

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
    SCHEMA_CANONICALIZATION_FAILED: 'schema_canonicalization_failed'
});

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
 * @returns {Object} Verification result
 */
export function verifySchemaOffline(schema, signatureB64, domain, toolId, discovery, revocation, pinStore) {
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
