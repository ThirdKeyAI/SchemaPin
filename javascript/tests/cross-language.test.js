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

// ---------------------------------------------------------------------------
// Fixed ECDSA signature vector (SP-2) and key-policy fixtures (SP-10, SP-19)
// ---------------------------------------------------------------------------

import { KeyManager, SignatureManager } from '../src/crypto.js';

const SIGNATURES = resolve(HERE, '..', '..', 'tests', 'cross-language', 'signatures');
const KEYS = resolve(HERE, '..', '..', 'tests', 'cross-language', 'keys');

describe('cross-language signature vector', () => {
    const v = JSON.parse(readFileSync(join(SIGNATURES, 'schema-signature.json'), 'utf-8'));

    test('fixed P-256 schema signature verifies', () => {
        const canonical = SchemaPinCore.canonicalizeSchema(v.schema);
        assert.strictEqual(canonical, v.canonical);
        const digest = SchemaPinCore.hashCanonical(canonical);
        assert.strictEqual(digest.toString('hex'), v.sha256);
        assert.strictEqual(KeyManager.calculateKeyFingerprint(v.public_key_pem), v.key_fingerprint);
        assert.strictEqual(SignatureManager.verifySchemaSignature(digest, v.signature, v.public_key_pem), true);
    });

    test('tampered schema and DER trailing bytes are rejected', () => {
        const digest = SchemaPinCore.hashCanonical(v.canonical);
        const tampered = SchemaPinCore.canonicalizeAndHash(v.tampered_schema);
        assert.strictEqual(SignatureManager.verifySchemaSignature(tampered, v.signature, v.public_key_pem), false);
        assert.strictEqual(
            SignatureManager.verifySchemaSignature(digest, v.signature_with_trailing_byte, v.public_key_pem),
            false
        );
    });

    for (const name of ['reject-p384-public.pem', 'reject-rsa2048-public.pem']) {
        test(`non-P-256 key rejected: ${name}`, () => {
            const pem = readFileSync(join(KEYS, name), 'utf-8');
            assert.throws(() => KeyManager.loadPublicKeyPem(pem), /only prime256v1|not an ECDSA key/);
            assert.throws(() => KeyManager.calculateKeyFingerprint(pem), /only prime256v1|not an ECDSA key/);
            const digest = SchemaPinCore.hashCanonical(v.canonical);
            assert.strictEqual(SignatureManager.verifySignature(digest, v.signature, pem), false);
        });
    }
});
