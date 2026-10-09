/**
 * Tests for core SchemaPin functionality.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import { SchemaPinCore, CanonicalizationError } from '../src/core.js';

describe('SchemaPinCore', () => {
    test('canonicalizeSchema - basic', () => {
        const schema = {
            description: 'Calculates the sum',
            name: 'calculate_sum',
            parameters: { b: 'integer', a: 'integer' }
        };
        
        const expected = '{"description":"Calculates the sum","name":"calculate_sum","parameters":{"a":"integer","b":"integer"}}';
        const result = SchemaPinCore.canonicalizeSchema(schema);
        
        assert.strictEqual(result, expected);
    });

    test('canonicalizeSchema - nested objects', () => {
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
        
        // Should have sorted keys at all levels
        assert(result.includes('"config":{"retries":3,"timeout":30}'));
        assert(result.startsWith('{"name":"complex_tool"'));
    });

    test('canonicalizeSchema - unicode characters', () => {
        const schema = {
            name: 'unicode_tool',
            description: 'Tool with émojis 🔧 and ñoñó'
        };
        
        const result = SchemaPinCore.canonicalizeSchema(schema);
        
        // Should preserve Unicode characters
        assert(result.includes('émojis 🔧'));
        assert(result.includes('ñoñó'));
    });

    test('hashCanonical', () => {
        const canonical = '{"name":"test","value":42}';
        const hashResult = SchemaPinCore.hashCanonical(canonical);
        
        // Should return 32 bytes (256 bits)
        assert.strictEqual(hashResult.length, 32);
        assert(Buffer.isBuffer(hashResult));
    });

    test('canonicalizeAndHash', () => {
        const schema = { name: 'test', value: 42 };
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
        const schema = { name: 'test', value: 42 };
        
        const hash1 = SchemaPinCore.canonicalizeAndHash(schema);
        const hash2 = SchemaPinCore.canonicalizeAndHash(schema);
        
        // Should produce identical hashes
        assert(hash1.equals(hash2));
    });
});
describe('strict canonicalization (SP-3/SP-4/SP-5 regressions)', () => {
    test('preserves __proto__ keys instead of invoking the prototype setter', () => {
        const parsed = SchemaPinCore.parseSchemaJson('{"__proto__":{"polluted":1},"name":"x"}');
        assert.strictEqual(
            SchemaPinCore.canonicalizeSchema(parsed),
            '{"__proto__":{"polluted":1},"name":"x"}'
        );
        // A benign schema must not share bytes with one carrying __proto__.
        assert.notStrictEqual(
            SchemaPinCore.canonicalizeSchema(parsed),
            SchemaPinCore.canonicalizeSchema({ name: 'x' })
        );
        assert.strictEqual(({}).polluted, undefined);
        // Also handles objects produced by the built-in JSON.parse.
        assert.strictEqual(
            SchemaPinCore.canonicalizeSchema(JSON.parse('{"__proto__":{"polluted":1},"name":"x"}')),
            '{"__proto__":{"polluted":1},"name":"x"}'
        );
    });

    test('sorts keys by code point, not UTF-16 code unit', () => {
        const canonical = SchemaPinCore.canonicalizeSchema({ '\u{1F600}': 1, '￿': 2, z: 3 });
        assert.strictEqual(canonical, '{"z":3,"￿":2,"\u{1F600}":1}');
    });

    test('emits < > & and U+2028/U+2029 literally', () => {
        assert.strictEqual(
            SchemaPinCore.canonicalizeSchema({ s: '<a>&\u2028\u2029' }),
            '{"s":"<a>&\u2028\u2029"}'
        );
    });

    test('formats numbers per ES6 and rejects unsafe magnitudes', () => {
        assert.strictEqual(SchemaPinCore.canonicalizeSchema([1.0, 1e-7, 0.000001, 1e3, -0]), '[1,1e-7,0.000001,1000,0]');
        assert.throws(() => SchemaPinCore.canonicalizeSchema({ a: 2 ** 53 }), CanonicalizationError);
        assert.throws(() => SchemaPinCore.canonicalizeSchema({ a: NaN }), CanonicalizationError);
        assert.throws(() => SchemaPinCore.canonicalizeSchema({ a: Infinity }), CanonicalizationError);
    });

    test('rejects duplicate keys and lone surrogates at parse time', () => {
        assert.throws(() => SchemaPinCore.parseSchemaJson('{"a":1,"a":2}'), CanonicalizationError);
        assert.throws(() => SchemaPinCore.parseSchemaJson('{"a":"\\ud800"}'), CanonicalizationError);
        assert.throws(() => SchemaPinCore.canonicalizeSchema({ a: '\ud800' }), CanonicalizationError);
    });
});
