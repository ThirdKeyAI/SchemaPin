/**
 * Cross-compatibility tests between JavaScript and Python implementations.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'fs';
import { SchemaPinCore } from '../src/core.js';
import { KeyManager, SignatureManager } from '../src/crypto.js';

describe('Cross-Compatibility with Python Implementation', () => {
    test('verify Python-generated signature with JavaScript', () => {
        try {
            // Load Python-generated demo files
            const schemaData = JSON.parse(readFileSync('../python/examples/demo_schema_signed.json', 'utf8'));
            const wellKnownData = JSON.parse(readFileSync('../python/examples/demo_well_known.json', 'utf8'));
            
            const schema = schemaData.schema;
            const signature = schemaData.signature;
            const publicKeyPem = wellKnownData.public_key_pem;
            
            // Verify the signature using JavaScript implementation
            const schemaHash = SchemaPinCore.canonicalizeAndHash(schema);
            const publicKey = KeyManager.loadPublicKeyPem(publicKeyPem);
            const isValid = SignatureManager.verifySchemaSignature(schemaHash, signature, publicKey);
            
            assert.strictEqual(isValid, true, 'JavaScript should verify Python-generated signature');
            
        } catch (error) {
            if (error.code === 'ENOENT') {
                console.log('⚠️  Python demo files not found - run Python examples first');
                // Skip test if Python files don't exist
                return;
            }
            throw error;
        }
    });

    test('canonicalization produces same result as Python', () => {
        // Test with the same schema structure used in Python tests
        const schema = {
            description: 'Calculates the sum',
            name: 'calculate_sum', 
            parameters: { b: 'integer', a: 'integer' }
        };
        
        const expected = '{"description":"Calculates the sum","name":"calculate_sum","parameters":{"a":"integer","b":"integer"}}';
        const result = SchemaPinCore.canonicalizeSchema(schema);
        
        assert.strictEqual(result, expected, 'Canonicalization should match Python output');
    });

    test('nested object canonicalization matches Python', () => {
        const schema = {
            name: 'complex_tool',
            parameters: {
                config: {
                    timeout: 30,
                    retries: 3
                },
                data: ['item1', 'item2']
            }
        };
        
        const result = SchemaPinCore.canonicalizeSchema(schema);
        
        // Should have sorted keys at all levels like Python
        assert(result.includes('"config":{"retries":3,"timeout":30}'));
        assert(result.startsWith('{"name":"complex_tool"'));
    });

    test('unicode handling matches Python', () => {
        const schema = {
            name: 'unicode_tool',
            description: 'Tool with émojis 🔧 and ñoñó'
        };
        
        const result = SchemaPinCore.canonicalizeSchema(schema);
        
        // Should preserve Unicode characters like Python
        assert(result.includes('émojis 🔧'));
        assert(result.includes('ñoñó'));
        assert(result.includes('"description":"Tool with émojis 🔧 and ñoñó"'));
    });

    test('key format compatibility', () => {
        // Generate keys and ensure they're in compatible PEM format
        const { privateKey, publicKey } = KeyManager.generateKeypair();
        
        // Keys should be in standard PEM format compatible with Python
        assert(privateKey.includes('-----BEGIN PRIVATE KEY-----'));
        assert(privateKey.includes('-----END PRIVATE KEY-----'));
        assert(publicKey.includes('-----BEGIN PUBLIC KEY-----'));
        assert(publicKey.includes('-----END PUBLIC KEY-----'));
        
        // Should be able to round-trip through PEM format
        const loadedPrivate = KeyManager.loadPrivateKeyPem(privateKey);
        const loadedPublic = KeyManager.loadPublicKeyPem(publicKey);
        
        assert.strictEqual(loadedPrivate, privateKey);
        assert.strictEqual(loadedPublic, publicKey);
    });
});