/**
 * Public key discovery via .well-known URIs per RFC 8615.
 */

import { KeyManager } from './crypto.js';
import { InvalidDomainError, validateDomain } from './domain.js';
import { checkRevocation, fetchRevocationDocument, RevocationFetchError } from './revocation.js';
import { DEFAULT_TIMEOUT_MS, fetchJson } from './transport.js';

/**
 * Handles public key discovery from .well-known endpoints.
 */
export class PublicKeyDiscovery {
    /**
     * Construct .well-known URI for SchemaPin public key discovery.
     * 
     * @param {string} domain - Tool provider domain
     * @returns {string} Full .well-known URI
     */
    static constructWellKnownUrl(domain) {
        if (typeof domain !== 'string') {
            throw new InvalidDomainError('domain must be a string');
        }
        if (domain.startsWith('http://')) {
            throw new InvalidDomainError('SchemaPin discovery requires https; http:// is not permitted');
        }
        if (domain.startsWith('https://')) {
            domain = domain.slice('https://'.length).replace(/\/+$/, '');
        }
        return `https://${validateDomain(domain)}/.well-known/schemapin.json`;
    }

    /**
     * Validate .well-known response structure.
     * 
     * @param {Object} responseData - Parsed JSON response
     * @returns {boolean} True if response is valid, false otherwise
     */
    static validateWellKnownResponse(responseData) {
        if (responseData === null || typeof responseData !== 'object' || Array.isArray(responseData)) {
            return false;
        }
        const requiredFields = ['schema_version', 'public_key_pem'];
        return requiredFields.every(field => field in responseData);
    }

    /**
     * Fetch and validate .well-known/schemapin.json from domain.
     * 
     * @param {string} domain - Tool provider domain
     * @param {number} timeout - Request timeout in milliseconds (default: 10000)
     * @returns {Promise<Object|null>} Parsed response data if valid, null otherwise
     */
    static async fetchWellKnown(domain, timeout = DEFAULT_TIMEOUT_MS) {
        try {
            const url = this.constructWellKnownUrl(domain);
            const data = await fetchJson(url, timeout);
            if (this.validateWellKnownResponse(data)) {
                return data;
            }
            return null;
        } catch {
            return null;
        }
    }

    /**
     * Get public key PEM from domain's .well-known endpoint.
     * 
     * @param {string} domain - Tool provider domain
     * @param {number} timeout - Request timeout in milliseconds (default: 10000)
     * @returns {Promise<string|null>} PEM-encoded public key if found, null otherwise
     */
    static async getPublicKeyPem(domain, timeout = DEFAULT_TIMEOUT_MS) {
        const wellKnownData = await this.fetchWellKnown(domain, timeout);
        if (wellKnownData) {
            return wellKnownData.public_key_pem;
        }
        return null;
    }

    /**
     * Get developer information from .well-known endpoint.
     * 
     * @param {string} domain - Tool provider domain
     * @param {number} timeout - Request timeout in milliseconds (default: 10000)
     * @returns {Promise<Object|null>} Object with developer info if available, null otherwise
     */
    static async getDeveloperInfo(domain, timeout = DEFAULT_TIMEOUT_MS) {
        const wellKnownData = await this.fetchWellKnown(domain, timeout);
        if (wellKnownData) {
            return {
                developer_name: wellKnownData.developer_name || 'Unknown',
                schema_version: wellKnownData.schema_version || '1.0',
                contact: wellKnownData.contact || ''
            };
        }
        return null;
    }

    /**
     * Check if a public key is in the revocation list.
     *
     * @param {string} publicKeyPem - PEM-encoded public key string
     * @param {Array<string>} revokedKeys - Array of revoked key fingerprints
     * @returns {boolean} True if key is revoked, false otherwise
     */
    static checkKeyRevocation(publicKeyPem, revokedKeys) {
        if (!revokedKeys || revokedKeys.length === 0) {
            return false;
        }

        try {
            const fingerprint = KeyManager.calculateKeyFingerprint(publicKeyPem);
            return revokedKeys.includes(fingerprint);
        } catch {
            // A key that cannot be fingerprinted cannot be trusted either.
            return true;
        }
    }

    /**
     * Get revoked keys list from domain's .well-known endpoint.
     *
     * @param {string} domain - Tool provider domain
     * @param {number} timeout - Request timeout in milliseconds (default: 10000)
     * @returns {Promise<Array<string>|null>} Array of revoked key fingerprints if available, null otherwise
     */
    static async getRevokedKeys(domain, timeout = DEFAULT_TIMEOUT_MS) {
        const wellKnownData = await this.fetchWellKnown(domain, timeout);
        if (wellKnownData) {
            return wellKnownData.revoked_keys || [];
        }
        return null;
    }

    /**
     * Validate that a public key is not revoked (fail-closed).
     *
     * Consults both the inline `revoked_keys` list and, when the discovery
     * document declares one, the standalone `revocation_endpoint`. If either
     * cannot be fetched the key is treated as not validated and `false` is
     * returned, unless `allowUnreachable` is true.
     *
     * @param {string} publicKeyPem - PEM-encoded public key string
     * @param {string} domain - Tool provider domain
     * @param {number} timeout - Request timeout in milliseconds (default: 10000)
     * @param {boolean} [allowUnreachable=false] - Treat fetch failures as "not revoked"
     * @returns {Promise<boolean>} True if the key is confirmed not revoked
     */
    static async validateKeyNotRevoked(publicKeyPem, domain, timeout = DEFAULT_TIMEOUT_MS, allowUnreachable = false) {
        const wellKnown = await this.fetchWellKnown(domain, timeout);
        if (wellKnown === null) {
            return allowUnreachable;
        }
        if (this.checkKeyRevocation(publicKeyPem, wellKnown.revoked_keys || [])) {
            return false;
        }
        const endpoint = wellKnown.revocation_endpoint;
        if (endpoint) {
            let doc;
            try {
                doc = await fetchRevocationDocument(endpoint, timeout);
            } catch (e) {
                if (e instanceof RevocationFetchError) {
                    return allowUnreachable;
                }
                throw e;
            }
            try {
                checkRevocation(doc, KeyManager.calculateKeyFingerprint(publicKeyPem));
            } catch {
                return false;
            }
        }
        return true;
    }
}