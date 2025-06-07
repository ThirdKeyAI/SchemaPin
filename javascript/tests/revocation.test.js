/**
 * Tests for key revocation functionality.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import { KeyManager } from '../src/crypto.js';
import { PublicKeyDiscovery } from '../src/discovery.js';
import { createWellKnownResponse } from '../src/utils.js';

describe('Key Revocation', () => {
    test('calculate key fingerprint', () => {
        // Generate a test key pair
        const { privateKey, publicKey } = KeyManager.generateKeypair();
        
        // Calculate fingerprint
        const fingerprint = KeyManager.calculateKeyFingerprint(publicKey);
        
        // Verify format
        assert(fingerprint.startsWith('sha256:'));
        assert.strictEqual(fingerprint.length, 71); // 'sha256:' + 64 hex chars
        
        // Verify consistency
        const fingerprint2 = KeyManager.calculateKeyFingerprint(publicKey);
        assert.strictEqual(fingerprint, fingerprint2);
    });

    test('check key revocation with empty list', () => {
        // Generate a test key
        const { publicKey } = KeyManager.generateKeypair();
        
        // Empty revocation list should return false
        assert.strictEqual(PublicKeyDiscovery.checkKeyRevocation(publicKey, []), false);
    });

    test('check key revocation not in list', () => {
        // Generate test keys
        const { publicKey: publicKey1 } = KeyManager.generateKeypair();
        const { publicKey: publicKey2 } = KeyManager.generateKeypair();
        
        const fingerprint2 = KeyManager.calculateKeyFingerprint(publicKey2);
        
        // Key1 should not be revoked when only key2 is in revocation list
        const revokedKeys = [fingerprint2];
        assert.strictEqual(PublicKeyDiscovery.checkKeyRevocation(publicKey1, revokedKeys), false);
    });

    test('check key revocation in list', () => {
        // Generate a test key
        const { publicKey } = KeyManager.generateKeypair();
        const fingerprint = KeyManager.calculateKeyFingerprint(publicKey);
        
        // Key should be revoked when in revocation list
        const revokedKeys = [fingerprint];
        assert.strictEqual(PublicKeyDiscovery.checkKeyRevocation(publicKey, revokedKeys), true);
    });

    test('check key revocation with multiple keys', () => {
        // Generate test keys
        const { publicKey: publicKey1 } = KeyManager.generateKeypair();
        const { publicKey: publicKey2 } = KeyManager.generateKeypair();
        const { publicKey: publicKey3 } = KeyManager.generateKeypair();
        
        const fingerprint1 = KeyManager.calculateKeyFingerprint(publicKey1);
        const fingerprint2 = KeyManager.calculateKeyFingerprint(publicKey2);
        const fingerprint3 = KeyManager.calculateKeyFingerprint(publicKey3);
        
        // Key2 should be revoked when in list with other keys
        const revokedKeys = [fingerprint1, fingerprint2, fingerprint3];
        assert.strictEqual(PublicKeyDiscovery.checkKeyRevocation(publicKey2, revokedKeys), true);
    });

    test('create well-known response with revoked keys', () => {
        // Generate test data
        const { publicKey } = KeyManager.generateKeypair();
        
        const revokedKeys = [
            "sha256:abc123def456",
            "sha256:789xyz012uvw"
        ];
        
        // Create response with revoked keys
        const response = createWellKnownResponse(
            publicKey,
            "Test Developer",
            "test@example.com",
            revokedKeys,
            "1.1"
        );
        
        // Verify response structure
        assert.strictEqual(response.schema_version, '1.1');
        assert.strictEqual(response.developer_name, 'Test Developer');
        assert.strictEqual(response.public_key_pem, publicKey);
        assert.strictEqual(response.contact, 'test@example.com');
        assert.deepStrictEqual(response.revoked_keys, revokedKeys);
    });

    test('create well-known response without revoked keys', () => {
        // Generate test data
        const { publicKey } = KeyManager.generateKeypair();
        
        // Create response without revoked keys
        const response = createWellKnownResponse(
            publicKey,
            "Test Developer"
        );
        
        // Verify response structure
        assert.strictEqual(response.schema_version, '1.1');
        assert.strictEqual(response.developer_name, 'Test Developer');
        assert.strictEqual(response.public_key_pem, publicKey);
        assert.strictEqual(response.revoked_keys, undefined);
    });

    test('create well-known response with empty revoked keys', () => {
        // Generate test data
        const { publicKey } = KeyManager.generateKeypair();
        
        // Create response with empty revoked keys
        const response = createWellKnownResponse(
            publicKey,
            "Test Developer",
            null,
            []
        );
        
        // Verify response structure (empty list should not be included)
        assert.strictEqual(response.schema_version, '1.1');
        assert.strictEqual(response.developer_name, 'Test Developer');
        assert.strictEqual(response.public_key_pem, publicKey);
        assert.strictEqual(response.revoked_keys, undefined);
    });

    test('backward compatibility with schema version 1.0', () => {
        // Generate test data
        const { publicKey } = KeyManager.generateKeypair();
        
        // Create response with schema version 1.0
        const response = createWellKnownResponse(
            publicKey,
            "Test Developer",
            null,
            null,
            "1.0"
        );
        
        // Verify response structure
        assert.strictEqual(response.schema_version, '1.0');
        assert.strictEqual(response.developer_name, 'Test Developer');
        assert.strictEqual(response.public_key_pem, publicKey);
        assert.strictEqual(response.revoked_keys, undefined);
    });

    test('fingerprint consistency between implementations', () => {
        // This test would ideally compare with Python implementation
        // For now, we test internal consistency
        const { publicKey } = KeyManager.generateKeypair();
        
        const fingerprint1 = KeyManager.calculateKeyFingerprint(publicKey);
        const fingerprint2 = KeyManager.calculateKeyFingerprint(publicKey);
        
        assert.strictEqual(fingerprint1, fingerprint2);
        
        // Verify format matches expected pattern
        assert(/^sha256:[a-f0-9]{64}$/.test(fingerprint1));
    });
});