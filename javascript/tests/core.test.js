/**
 * Tests for core SchemaPin functionality.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import { SchemaPinCore } from '../src/core.js';

describe('SchemaPinCore', () => {
    test('canonicalizeSchema - basic', () => {
        const schema = {
            description: "Calculates the sum",
            name: "calculate_sum",
            parameters: { b: "integer", a: "integer" }
        };
        
        const expected = '{"description":"Calculates the sum","name":"calculate_sum","parameters":{"a":"integer","b":"integer"}}';
        const result = SchemaPinCore.canonicalizeSchema(schema);
        
        assert.strictEqual(result, expected);
    });

    test('canonicalizeSchema - nested objects', () => {
        const schema = {
            name: "complex_tool",
            parameters: {
                config: {
                    timeout: 30,
                    retries: 3
                },
                data: ["item1", "item2"]
            }
        };
        
        const result = SchemaPinCore.canonicalizeSchema(schema);
        
        // Should have sorted keys at all levels
        assert(result.includes('"config":{"retries":3,"timeout":30}'));
        assert(result.startsWith('{"name":"complex_tool"'));
    });

    test('canonicalizeSchema - unicode characters', () => {
        const schema = {
            name: "unicode_tool",
            description: "Tool with émojis 🔧 and ñoñó"
        };
        
        const result = SchemaPinCore.canonicalizeSchema(schema);
        
        // Should preserve Unicode characters
        assert(result.includes("émojis 🔧"));
        assert(result.includes("ñoñó"));
    });

    test('hashCanonical', () => {
        const canonical = '{"name":"test","value":42}';
        const hashResult = SchemaPinCore.hashCanonical(canonical);
        
        // Should return 32 bytes (256 bits)
        assert.strictEqual(hashResult.length, 32);
        assert(Buffer.isBuffer(hashResult));
    });

    test('canonicalizeAndHash', () => {
        const schema = { name: "test", value: 42 };
        const hashResult = SchemaPinCore.canonicalizeAndHash(schema);
        
        // Should return 32 bytes
        assert.strictEqual(hashResult.length, 32);
        assert(Buffer.isBuffer(hashResult));
    });

    test('canonicalization is deterministic', () => {
        const schema1 = { b: 2, a: 1 };
        const schema2 = { a: 1, b: 2 };
        
        const canonical1 = SchemaPinCore.canonicalizeSchema(schema1);
        const canonical2 = SchemaPinCore.canonicalizeSchema(schema2);
        
        // Should produce identical results regardless of input order
        assert.strictEqual(canonical1, canonical2);
    });

    test('hashing is deterministic', () => {
        const schema = { name: "test", value: 42 };
        
        const hash1 = SchemaPinCore.canonicalizeAndHash(schema);
        const hash2 = SchemaPinCore.canonicalizeAndHash(schema);
        
        // Should produce identical hashes
        assert(hash1.equals(hash2));
    });
});