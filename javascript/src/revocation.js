/**
 * Standalone revocation documents for SchemaPin v1.2.
 */

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
 * Fetch a standalone revocation document from a URL.
 *
 * @param {string} url - URL to fetch from
 * @param {number} timeout - Timeout in milliseconds (default: 10000)
 * @returns {Promise<Object|null>} Revocation document or null on failure
 */
export async function fetchRevocationDocument(url, timeout = 10000) {
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);

        const response = await fetch(url, { signal: controller.signal });
        clearTimeout(timeoutId);

        if (!response.ok) {
            return null;
        }

        return await response.json();
    } catch {
        return null;
    }
}
