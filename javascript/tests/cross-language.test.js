/**
 * Cross-language conformance: canonicalization corpus shared by all SDKs.
 *
 * Every vector under tests/cross-language/canonicalization/ is asserted by
 * the Python, JavaScript, Go and Rust suites.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { SchemaPinCore, CanonicalizationError } from '../src/core.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const CORPUS = resolve(HERE, '..', '..', 'tests', 'cross-language', 'canonicalization');

describe('cross-language canonicalization corpus', () => {
    const files = readdirSync(CORPUS).filter((f) => f.endsWith('.json')).sort();
    assert.ok(files.length > 0, 'corpus must not be empty');

    for (const file of files) {
        const vector = JSON.parse(readFileSync(join(CORPUS, file), 'utf-8'));
        test(vector.name, () => {
            if (vector.reject) {
                assert.throws(
                    () => SchemaPinCore.canonicalizeSchema(SchemaPinCore.parseSchemaJson(vector.input)),
                    CanonicalizationError
                );
                return;
            }
            const parsed = SchemaPinCore.parseSchemaJson(vector.input);
            const canonical = SchemaPinCore.canonicalizeSchema(parsed);
            assert.strictEqual(canonical, vector.expected_canonical);
            const digest = createHash('sha256').update(canonical, 'utf8').digest('hex');
            assert.strictEqual(digest, vector.expected_sha256);
            assert.strictEqual(
                SchemaPinCore.canonicalizeSchema(SchemaPinCore.parseSchemaJson(canonical)),
                canonical
            );
        });
    }
});
