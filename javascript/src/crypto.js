/**
 * Cryptographic operations for SchemaPin using ECDSA P-256.
 */

import { createSign, createVerify, generateKeyPairSync, createHash, createPublicKey } from 'crypto';

/**
 * Manages ECDSA P-256 key generation and serialization.
 */
export class KeyManager {
    /**
     * Generate new ECDSA P-256 key pair.
     * 
     * @returns {Object} Object with privateKey and publicKey
     */
    static generateKeypair() {
        const { privateKey, publicKey } = generateKeyPairSync('ec', {
            namedCurve: 'prime256v1', // P-256
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });
        
        return { privateKey, publicKey };
    }

    /**
     * Export private key to PEM format.
     * 
     * @param {string} privateKey - ECDSA private key in PEM format
     * @returns {string} PEM-encoded private key string
     */
    static exportPrivateKeyPem(privateKey) {
        return privateKey;
    }

    /**
     * Export public key to PEM format.
     * 
     * @param {string} publicKey - ECDSA public key in PEM format
     * @returns {string} PEM-encoded public key string
     */
    static exportPublicKeyPem(publicKey) {
        return publicKey;
    }

    /**
     * Load private key from PEM format.
     * 
     * @param {string} pemData - PEM-encoded private key string
     * @returns {string} ECDSA private key
     */
    static loadPrivateKeyPem(pemData) {
        return pemData;
    }

    /**
     * Load public key from PEM format.
     * 
     * @param {string} pemData - PEM-encoded public key string
     * @returns {string} ECDSA public key
     */
    static loadPublicKeyPem(pemData) {
        return pemData;
    }

    /**
     * Calculate SHA-256 fingerprint of public key.
     *
     * @param {string} publicKeyPem - PEM-encoded public key string
     * @returns {string} SHA-256 fingerprint in format 'sha256:hexstring'
     */
    static calculateKeyFingerprint(publicKeyPem) {
        // Convert PEM to DER format for consistent fingerprinting
        const keyObject = createPublicKey(publicKeyPem);
        const der = keyObject.export({ type: 'spki', format: 'der' });
        const hash = createHash('sha256').update(der).digest('hex');
        return `sha256:${hash}`;
    }
}

/**
 * Manages ECDSA signature creation and verification.
 */
export class SignatureManager {
    /**
     * Sign hash using ECDSA P-256 and return Base64-encoded signature.
     * 
     * @param {Buffer} hashBytes - SHA-256 hash to sign
     * @param {string} privateKey - ECDSA private key in PEM format
     * @returns {string} Base64-encoded signature
     */
    static signHash(hashBytes, privateKey) {
        const sign = createSign('SHA256');
        sign.update(hashBytes);
        const signature = sign.sign(privateKey);
        return signature.toString('base64');
    }

    /**
     * Verify ECDSA signature against hash.
     * 
     * @param {Buffer} hashBytes - Original SHA-256 hash
     * @param {string} signatureB64 - Base64-encoded signature
     * @param {string} publicKey - ECDSA public key in PEM format
     * @returns {boolean} True if signature is valid, false otherwise
     */
    static verifySignature(hashBytes, signatureB64, publicKey) {
        try {
            const verify = createVerify('SHA256');
            verify.update(hashBytes);
            const signature = Buffer.from(signatureB64, 'base64');
            return verify.verify(publicKey, signature);
        } catch (error) {
            return false;
        }
    }

    /**
     * Sign schema hash and return Base64 signature.
     * 
     * @param {Buffer} schemaHash - SHA-256 hash of canonical schema
     * @param {string} privateKey - ECDSA private key in PEM format
     * @returns {string} Base64-encoded signature
     */
    static signSchemaHash(schemaHash, privateKey) {
        return this.signHash(schemaHash, privateKey);
    }

    /**
     * Verify schema signature against hash.
     * 
     * @param {Buffer} schemaHash - SHA-256 hash of canonical schema
     * @param {string} signatureB64 - Base64-encoded signature
     * @param {string} publicKey - ECDSA public key in PEM format
     * @returns {boolean} True if signature is valid, false otherwise
     */
    static verifySchemaSignature(schemaHash, signatureB64, publicKey) {
        return this.verifySignature(schemaHash, signatureB64, publicKey);
    }
}