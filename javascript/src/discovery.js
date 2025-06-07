/**
 * Public key discovery via .well-known URIs per RFC 8615.
 */

import { KeyManager } from './crypto.js';

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
        if (!domain.startsWith('http://') && !domain.startsWith('https://')) {
            domain = `https://${domain}`;
        }
        return new URL('/.well-known/schemapin.json', domain).toString();
    }

    /**
     * Validate .well-known response structure.
     * 
     * @param {Object} responseData - Parsed JSON response
     * @returns {boolean} True if response is valid, false otherwise
     */
    static validateWellKnownResponse(responseData) {
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
    static async fetchWellKnown(domain, timeout = 10000) {
        try {
            const url = this.constructWellKnownUrl(domain);
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), timeout);
            
            const response = await fetch(url, {
                signal: controller.signal,
                headers: {
                    'Accept': 'application/json',
                    'User-Agent': 'SchemaPin/1.0'
                }
            });
            
            clearTimeout(timeoutId);
            
            if (!response.ok) {
                return null;
            }
            
            const data = await response.json();
            if (this.validateWellKnownResponse(data)) {
                return data;
            }
            return null;
            
        } catch (error) {
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
    static async getPublicKeyPem(domain, timeout = 10000) {
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
    static async getDeveloperInfo(domain, timeout = 10000) {
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
        } catch (error) {
            // If we can't calculate fingerprint, assume not revoked
            return false;
        }
    }

    /**
     * Get revoked keys list from domain's .well-known endpoint.
     *
     * @param {string} domain - Tool provider domain
     * @param {number} timeout - Request timeout in milliseconds (default: 10000)
     * @returns {Promise<Array<string>|null>} Array of revoked key fingerprints if available, null otherwise
     */
    static async getRevokedKeys(domain, timeout = 10000) {
        const wellKnownData = await this.fetchWellKnown(domain, timeout);
        if (wellKnownData) {
            return wellKnownData.revoked_keys || [];
        }
        return null;
    }

    /**
     * Validate that a public key is not revoked.
     *
     * @param {string} publicKeyPem - PEM-encoded public key string
     * @param {string} domain - Tool provider domain
     * @param {number} timeout - Request timeout in milliseconds (default: 10000)
     * @returns {Promise<boolean>} True if key is not revoked, false if revoked or error
     */
    static async validateKeyNotRevoked(publicKeyPem, domain, timeout = 10000) {
        const revokedKeys = await this.getRevokedKeys(domain, timeout);
        if (revokedKeys === null) {
            // If we can't fetch revocation list, assume not revoked
            return true;
        }

        return !this.checkKeyRevocation(publicKeyPem, revokedKeys);
    }
}