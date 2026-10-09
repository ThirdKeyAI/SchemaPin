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

// ---------------------------------------------------------------------------
// Skill-directory fixtures (SP-1, SP-12, SP-13, SP-14)
// ---------------------------------------------------------------------------

import { cpSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { SIGNATURE_FILENAME, canonicalizeSkill, canonicalizeSkillV1, loadSignature, verifySkillOffline } from '../src/skill.js';

const SKILL_FIXTURES = resolve(HERE, '..', '..', 'tests', 'cross-language', 'skill');

describe('cross-language skill fixtures', () => {
    const expected = JSON.parse(readFileSync(join(SKILL_FIXTURES, 'expected.json'), 'utf-8'));

    test('v1.4 fixture hashes and verifies', () => {
        const skillDir = join(SKILL_FIXTURES, expected.v14.skill_dir);
        const { rootHash, manifest } = canonicalizeSkill(skillDir);
        assert.strictEqual(`sha256:${rootHash.toString('hex')}`, expected.v14.skill_hash);
        assert.deepStrictEqual(manifest, expected.v14.file_manifest);
        const result = verifySkillOffline(skillDir, expected.discovery, null, null, null, null, expected.domain);
        assert.strictEqual(result.valid, true, JSON.stringify(result));
        assert.ok(!result.warnings.includes('legacy_signature_format'));
        assert.strictEqual(result.schema_version, '1.0.0');
    });

    test('v1.4 fixture: tampering any signed field or file fails', () => {
        const src = join(SKILL_FIXTURES, expected.v14.skill_dir);
        const dir = mkdtempSync(join(tmpdir(), 'skill-fixture-'));
        try {
            for (const field of expected.v14.signed_fields_tamper_must_fail) {
                const dst = join(dir, field);
                cpSync(src, dst, { recursive: true });
                const sig = loadSignature(dst);
                sig[field] = field === 'skill_hash' ? 'sha256:' + '00'.repeat(32) : 'tampered';
                writeFileSync(join(dst, SIGNATURE_FILENAME), JSON.stringify(sig), 'utf-8');
                assert.strictEqual(verifySkillOffline(dst, expected.discovery).valid, false, field);
            }
            const dst = join(dir, 'content');
            cpSync(src, dst, { recursive: true });
            writeFileSync(join(dst, 'scripts', 'run.sh'), '#!/bin/sh\nrm -rf /\n');
            assert.strictEqual(verifySkillOffline(dst, expected.discovery).valid, false);
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    test('legacy 1.3 fixture verifies with a warning', () => {
        const skillDir = join(SKILL_FIXTURES, expected.legacy_v13.skill_dir);
        const { rootHash, manifest } = canonicalizeSkillV1(skillDir);
        assert.strictEqual(`sha256:${rootHash.toString('hex')}`, expected.legacy_v13.skill_hash);
        assert.deepStrictEqual(manifest, expected.legacy_v13.file_manifest);
        const result = verifySkillOffline(skillDir, expected.discovery, null, null, null, null, expected.domain);
        assert.strictEqual(result.valid, true, JSON.stringify(result));
        assert.ok(result.warnings.includes('legacy_signature_format'));
    });
});
