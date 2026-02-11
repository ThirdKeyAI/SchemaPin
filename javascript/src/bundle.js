/**
 * Trust bundles for offline/air-gapped SchemaPin verification.
 */

/**
 * Create an empty trust bundle.
 *
 * @param {string} createdAt - ISO 8601 timestamp
 * @returns {Object} Trust bundle
 */
export function createTrustBundle(createdAt) {
    return {
        schemapin_bundle_version: '1.2',
        created_at: createdAt,
        documents: [],
        revocations: []
    };
}

/**
 * Create a flattened BundledDiscovery entry.
 * Merges domain with well-known fields at the same level.
 *
 * @param {string} domain - The domain
 * @param {Object} wellKnown - Well-known response fields
 * @returns {Object} Flattened bundled discovery entry
 */
export function createBundledDiscovery(domain, wellKnown) {
    return { domain, ...wellKnown };
}

/**
 * Find a discovery document in a bundle for a domain.
 *
 * @param {Object} bundle - Trust bundle
 * @param {string} domain - Domain to search for
 * @returns {Object|null} Well-known fields (without 'domain' key), or null
 */
export function findDiscovery(bundle, domain) {
    for (const doc of bundle.documents) {
        if (doc.domain === domain) {
            const { domain: _, ...rest } = doc;
            return rest;
        }
    }
    return null;
}

/**
 * Find a revocation document in a bundle for a domain.
 *
 * @param {Object} bundle - Trust bundle
 * @param {string} domain - Domain to search for
 * @returns {Object|null} Revocation document or null
 */
export function findRevocation(bundle, domain) {
    for (const rev of bundle.revocations) {
        if (rev.domain === domain) {
            return rev;
        }
    }
    return null;
}

/**
 * Parse a trust bundle from a JSON string.
 *
 * @param {string} jsonStr - JSON string
 * @returns {Object} Trust bundle
 */
export function parseTrustBundle(jsonStr) {
    return JSON.parse(jsonStr);
}
