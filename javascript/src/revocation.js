/**
 * Standalone revocation documents for SchemaPin v1.2.
 */

import { DEFAULT_TIMEOUT_MS, fetchJson, TransportError } from './transport.js';

/**
 * Thrown when a declared revocation endpoint cannot be fetched or parsed.
 *
 * Verification paths treat this as fail-closed (`DISCOVERY_FETCH_FAILED`)
 * unless the caller opts out with `allowUnreachableRevocation`.
 */
export class RevocationFetchError extends Error {
    constructor(message) {
        super(message);
        this.name = 'RevocationFetchError';
    }
}

/**
 * Revocation reason constants.
 */
export const RevocationReason = Object.freeze({
    KEY_COMPROMISE: 'key_compromise',
    SUPERSEDED: 'superseded',
    CESSATION_OF_OPERATION: 'cessation_of_operation',
    PRIVILEGE_WITHDRAWN: 'privilege_withdrawn'
});

/**
 * Build an empty revocation document for a domain.
 *
 * @param {string} domain - The domain
 * @returns {Object} Revocation document
 */
export function buildRevocationDocument(domain) {
    return {
        schemapin_version: '1.2',
        domain,
        updated_at: new Date().toISOString(),
        revoked_keys: []
    };
}

/**
 * Add a revoked key entry to a revocation document.
 *
 * @param {Object} doc - Revocation document
 * @param {string} fingerprint - Key fingerprint
 * @param {string} reason - RevocationReason value
 */
export function addRevokedKey(doc, fingerprint, reason) {
    const now = new Date().toISOString();
    doc.revoked_keys.push({
        fingerprint,
        revoked_at: now,
        reason
    });
    doc.updated_at = now;
}

/**
 * Check if a fingerprint is revoked in a standalone document.
 *
 * @param {Object} doc - Revocation document
 * @param {string} fingerprint - Key fingerprint to check
 * @throws {Error} If the key is revoked
 */
export function checkRevocation(doc, fingerprint) {
    for (const key of doc.revoked_keys) {
        if (key.fingerprint === fingerprint) {
            throw new Error(`Key ${fingerprint} is revoked: ${key.reason}`);
        }
    }
}

/**
 * Check revocation against both simple list and standalone document.
 *
 * @param {Array<string>|null} simpleRevoked - Simple revocation list
 * @param {Object|null} revocationDoc - Standalone revocation document
 * @param {string} fingerprint - Key fingerprint to check
 * @throws {Error} If the key is revoked in either source
 */
export function checkRevocationCombined(simpleRevoked, revocationDoc, fingerprint) {
    if (simpleRevoked && simpleRevoked.length > 0) {
        if (simpleRevoked.includes(fingerprint)) {
            throw new Error(`Key ${fingerprint} is in simple revocation list`);
        }
    }

    if (revocationDoc) {
        checkRevocation(revocationDoc, fingerprint);
    }
}

/**
 * Fetch a standalone revocation document from an https:// URL.
 *
 * Redirects are not followed, the response body is capped and the URL must
 * use https. Throws {@link RevocationFetchError} on any failure so that
 * callers fail closed; it never silently resolves to "no revocations".
 *
 * @param {string} url - URL to fetch from
 * @param {number} timeout - Timeout in milliseconds (default: 10000)
 * @returns {Promise<Object>} Revocation document
 * @throws {RevocationFetchError}
 */
export async function fetchRevocationDocument(url, timeout = DEFAULT_TIMEOUT_MS) {
    let data;
    try {
        data = await fetchJson(url, timeout);
    } catch (e) {
        if (e instanceof TransportError) {
            throw new RevocationFetchError(`failed to fetch revocation document ${url}: ${e.message}`);
        }
        throw e;
    }
    if (data === null || typeof data !== 'object' || !Array.isArray(data.revoked_keys) || typeof data.domain !== 'string') {
        throw new RevocationFetchError(`revocation document from ${url} is malformed`);
    }
    return data;
}
