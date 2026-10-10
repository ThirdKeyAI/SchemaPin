/**
 * Utility functions for SchemaPin operations.
 */

import { SchemaPinCore } from './core.js';
import { KeyManager, SignatureManager } from './crypto.js';
import { PublicKeyDiscovery } from './discovery.js';
import { validateDomain } from './domain.js';
import { KeyPinning } from './pinning.js';

/**
 * High-level workflow for tool developers to sign schemas.
 */
export class SchemaSigningWorkflow {
    /**
     * Initialize signing workflow with private key.
     * 
     * @param {string} privateKeyPem - PEM-encoded private key
     */
    constructor(privateKeyPem) {
        this.privateKey = KeyManager.loadPrivateKeyPem(privateKeyPem);
    }

    /**
     * Sign a tool schema and return Base64 signature.
     * 
     * @param {Object} schema - Tool schema object
     * @returns {string} Base64-encoded signature
     */
    signSchema(schema) {
        const schemaHash = SchemaPinCore.canonicalizeAndHash(schema);
        return SignatureManager.signSchemaHash(schemaHash, this.privateKey);
    }
}

/**
 * High-level workflow for clients to verify schemas.
 *
 * @deprecated Built on the legacy `KeyPinning` store. Prefer
 * `verifySchemaWithResolver` with a `KeyPinStore`, which pins by fingerprint
 * only after a successful verification and returns a structured result.
 */
export class SchemaVerificationWorkflow {
    /**
     * Initialize verification workflow.
     * 
     * @param {string|null} pinningDbPath - Optional path to key pinning database
     */
    constructor(pinningDbPath = null) {
        this.pinning = new KeyPinning(pinningDbPath);
        this.discovery = new PublicKeyDiscovery();
    }

    /**
     * Verify schema signature with key pinning support.
     * 
     * @param {Object} schema - Tool schema object
     * @param {string} signatureB64 - Base64-encoded signature
     * @param {string} toolId - Unique tool identifier
     * @param {string} domain - Tool provider domain
     * @param {boolean} autoPin - Whether to auto-pin keys on first use
     * @returns {Promise<Object>} Object with verification result and metadata
     */
    async verifySchema(schema, signatureB64, toolId, domain, autoPin = false) {
        const result = {
            valid: false,
            pinned: false,
            first_use: false,
            error: null,
            developer_info: null
        };

        try {
            domain = validateDomain(domain);

            // Check for a key pinned for this tool at this domain
            const pinnedKeyPem = this.pinning.getPinnedKey(toolId, domain);
            let publicKey;
            let publicKeyPem;
            let shouldPin = false;

            if (pinnedKeyPem) {
                // Use pinned key, but check if it's been revoked (fail-closed)
                const isNotRevoked = await PublicKeyDiscovery.validateKeyNotRevoked(pinnedKeyPem, domain);
                if (!isNotRevoked) {
                    result.error = 'Pinned public key has been revoked or its status is unavailable';
                    return result;
                }

                publicKey = KeyManager.loadPublicKeyPem(pinnedKeyPem);
                publicKeyPem = pinnedKeyPem;
                result.pinned = true;
            } else {
                // First use - discover key
                publicKeyPem = await this.discovery.getPublicKeyPem(domain);
                if (!publicKeyPem) {
                    result.error = 'Could not discover public key';
                    return result;
                }

                // Check if key is revoked (fail-closed)
                const isNotRevoked = await PublicKeyDiscovery.validateKeyNotRevoked(publicKeyPem, domain);
                if (!isNotRevoked) {
                    result.error = 'Public key has been revoked or its status is unavailable';
                    return result;
                }

                publicKey = KeyManager.loadPublicKeyPem(publicKeyPem);
                result.first_use = true;
                result.developer_info = await this.discovery.getDeveloperInfo(domain);
                shouldPin = autoPin;
            }

            // Verify signature before anything is pinned
            const schemaHash = SchemaPinCore.canonicalizeAndHash(schema);
            result.valid = SignatureManager.verifySchemaSignature(
                schemaHash, signatureB64, publicKey
            );

            // Auto-pin only after a successful verification
            if (result.valid && shouldPin) {
                const developerName = result.developer_info ? result.developer_info.developer_name : null;
                this.pinning.pinKey(toolId, publicKeyPem, domain, developerName);
                result.pinned = true;
            }

            // Update verification timestamp if valid and pinned
            if (result.valid && result.pinned) {
                this.pinning.updateLastVerified(toolId, domain);
            }

        } catch (error) {
            result.error = error.message;
        }

        return result;
    }

    /**
     * Manually pin key for a tool.
     * 
     * @param {string} toolId - Unique tool identifier
     * @param {string} domain - Tool provider domain
     * @param {string|null} developerName - Optional developer name
     * @returns {Promise<boolean>} True if key was pinned successfully, false otherwise
     */
    async pinKeyForTool(toolId, domain, developerName = null) {
        const publicKeyPem = await this.discovery.getPublicKeyPem(domain);
        if (publicKeyPem) {
            return this.pinning.pinKey(toolId, publicKeyPem, domain, developerName);
        }
        return false;
    }
}

/**
 * Create .well-known/schemapin.json response structure.
 *
 * @param {string} publicKeyPem - PEM-encoded public key
 * @param {string} developerName - Developer or organization name
 * @param {string|null} contact - Optional contact information
 * @param {Array<string>|null} revokedKeys - Optional array of revoked key fingerprints
 * @param {string} schemaVersion - Schema version (default: "1.2")
 * @param {string|null} revocationEndpoint - Optional URL for standalone revocation document
 * @returns {Object} Object suitable for .well-known response
 */
export function createWellKnownResponse(publicKeyPem, developerName, contact = null, revokedKeys = null, schemaVersion = '1.2', revocationEndpoint = null) {
    const response = {
        schema_version: schemaVersion,
        developer_name: developerName,
        public_key_pem: publicKeyPem
    };

    if (contact) {
        response.contact = contact;
    }

    if (revokedKeys && revokedKeys.length > 0) {
        response.revoked_keys = revokedKeys;
    }

    if (revocationEndpoint) {
        response.revocation_endpoint = revocationEndpoint;
    }

    return response;
}