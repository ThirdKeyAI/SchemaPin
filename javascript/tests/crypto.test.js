/**
 * Tests for cryptographic operations.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import { KeyManager, SignatureManager } from '../src/crypto.js';

describe('KeyManager', () => {
    test('generateKeypair', () => {
        const { privateKey, publicKey } = KeyManager.generateKeypair();
        
        // Keys should be valid PEM strings
        assert(typeof privateKey === 'string');
        assert(typeof publicKey === 'string');
        assert(privateKey.includes('-----BEGIN PRIVATE KEY-----'));
        assert(publicKey.includes('-----BEGIN PUBLIC KEY-----'));
    });

    test('exportPrivateKeyPem', () => {
        const { privateKey } = KeyManager.generateKeypair();
        const pemData = KeyManager.exportPrivateKeyPem(privateKey);
        
        // Should be valid PEM format
        assert(pemData.startsWith('-----BEGIN PRIVATE KEY-----'));
        assert(pemData.includes('-----END PRIVATE KEY-----'));
    });

    test('exportPublicKeyPem', () => {
        const { publicKey } = KeyManager.generateKeypair();
        const pemData = KeyManager.exportPublicKeyPem(publicKey);
        
        // Should be valid PEM format
        assert(pemData.startsWith('-----BEGIN PUBLIC KEY-----'));
        assert(pemData.includes('-----END PUBLIC KEY-----'));
    });

    test('loadPrivateKeyPem', () => {
        const { privateKey } = KeyManager.generateKeypair();
        const pemData = KeyManager.exportPrivateKeyPem(privateKey);
        
        // Should be able to load the exported key
        const loadedKey = KeyManager.loadPrivateKeyPem(pemData);
        assert(typeof loadedKey === 'string');
    });

    test('loadPublicKeyPem', () => {
        const { publicKey } = KeyManager.generateKeypair();
        const pemData = KeyManager.exportPublicKeyPem(publicKey);
        
        // Should be able to load the exported key
        const loadedKey = KeyManager.loadPublicKeyPem(pemData);
        assert(typeof loadedKey === 'string');
    });

    test('key roundtrip', () => {
        const { privateKey, publicKey } = KeyManager.generateKeypair();
        
        // Export and reload private key
        const privatePem = KeyManager.exportPrivateKeyPem(privateKey);
        const loadedPrivate = KeyManager.loadPrivateKeyPem(privatePem);
        
        // Export and reload public key
        const publicPem = KeyManager.exportPublicKeyPem(publicKey);
        const loadedPublic = KeyManager.loadPublicKeyPem(publicPem);
        
        // Keys should be functionally equivalent
        assert.strictEqual(KeyManager.exportPrivateKeyPem(loadedPrivate), privatePem);
        assert.strictEqual(KeyManager.exportPublicKeyPem(loadedPublic), publicPem);
    });
});

describe('SignatureManager', () => {
    test('signHash and verifySignature', () => {
        const { privateKey, publicKey } = KeyManager.generateKeypair();
        const testHash = Buffer.from('test_hash_32_bytes_exactly_here!', 'utf8');
        
        // Sign the hash
        const signatureB64 = SignatureManager.signHash(testHash, privateKey);
        
        // Signature should be Base64 encoded
        assert(typeof signatureB64 === 'string');
        
        // Verify the signature
        const isValid = SignatureManager.verifySignature(testHash, signatureB64, publicKey);
        assert.strictEqual(isValid, true);
    });

    test('verifySignature - invalid signature', () => {
        const { privateKey, publicKey } = KeyManager.generateKeypair();
        const testHash = Buffer.from('test_hash_32_bytes_exactly_here!', 'utf8');
        
        // Create valid signature
        const signatureB64 = SignatureManager.signHash(testHash, privateKey);
        
        // Modify signature to make it invalid
        const invalidSignature = signatureB64.slice(0, -4) + 'XXXX';
        
        // Should fail verification
        const isValid = SignatureManager.verifySignature(testHash, invalidSignature, publicKey);
        assert.strictEqual(isValid, false);
    });

    test('verifySignature - wrong hash', () => {
        const { privateKey, publicKey } = KeyManager.generateKeypair();
        const originalHash = Buffer.from('original_hash_32_bytes_exactly!', 'utf8');
        const differentHash = Buffer.from('different_hash_32_bytes_exactly', 'utf8');
        
        // Sign original hash
        const signatureB64 = SignatureManager.signHash(originalHash, privateKey);
        
        // Try to verify with different hash
        const isValid = SignatureManager.verifySignature(differentHash, signatureB64, publicKey);
        assert.strictEqual(isValid, false);
    });

    test('verifySignature - wrong key', () => {
        const { privateKey: privateKey1 } = KeyManager.generateKeypair();
        const { publicKey: publicKey2 } = KeyManager.generateKeypair();
        const testHash = Buffer.from('test_hash_32_bytes_exactly_here!', 'utf8');
        
        // Sign with first key
        const signatureB64 = SignatureManager.signHash(testHash, privateKey1);
        
        // Try to verify with second key
        const isValid = SignatureManager.verifySignature(testHash, signatureB64, publicKey2);
        assert.strictEqual(isValid, false);
    });

    test('schema signature methods', () => {
        const { privateKey, publicKey } = KeyManager.generateKeypair();
        const schemaHash = Buffer.from('schema_hash_32_bytes_exactly_!!', 'utf8');
        
        // Sign schema hash
        const signatureB64 = SignatureManager.signSchemaHash(schemaHash, privateKey);
        
        // Verify schema signature
        const isValid = SignatureManager.verifySchemaSignature(schemaHash, signatureB64, publicKey);
        assert.strictEqual(isValid, true);
    });

    test('signatures are non-deterministic', () => {
        const { privateKey, publicKey } = KeyManager.generateKeypair();
        const testHash = Buffer.from('test_hash_32_bytes_exactly_here!', 'utf8');
        
        // Note: ECDSA signatures are NOT deterministic by design (they use random nonce)
        // This test verifies that different signatures for same data still verify correctly
        const signature1 = SignatureManager.signHash(testHash, privateKey);
        const signature2 = SignatureManager.signHash(testHash, privateKey);
        
        // Signatures should be different (due to random nonce)
        assert.notStrictEqual(signature1, signature2);
        
        // But both should verify correctly
        assert.strictEqual(SignatureManager.verifySignature(testHash, signature1, publicKey), true);
        assert.strictEqual(SignatureManager.verifySignature(testHash, signature2, publicKey), true);
    });
});