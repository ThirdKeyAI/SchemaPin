/**
 * Tests for v1.4 A2A trust-bundle distribution (sign / verify / merge /
 * JSON-RPC envelope), mirroring rust/src/bundle.rs tests, plus a
 * cross-language fixture test proving canonicalization agreement.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

import {
    signTrustBundle,
    verifyTrustBundle,
    mergeTrustBundles,
    buildTrustBundleRequest,
    buildTrustBundleResponse,
    parseTrustBundleResponse,
    createTrustBundle,
    createBundledDiscovery
} from '../src/bundle.js';
import { ErrorCode, KeyPinStore } from '../src/verification.js';
import { KeyManager } from '../src/crypto.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
// javascript/tests -> repo root is two levels up.
const REPO_ROOT = resolve(__dirname, '..', '..');
const FIXTURE_PATH = resolve(REPO_ROOT, 'tests', 'cross-language', 'signed_bundle.json');

function makeBundle(domain, createdAt) {
    const wellKnown = {
        schema_version: '1.2',
        developer_name: 'Example',
        public_key_pem: '-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----',
        revoked_keys: []
    };
    const bundle = createTrustBundle(createdAt);
    bundle.documents.push(createBundledDiscovery(domain, wellKnown));
    return bundle;
}

describe('TrustBundle distribution (v1.4)', () => {
    it('sign/verify roundtrip', () => {
        const { privateKey } = KeyManager.generateKeypair();
        const bundle = makeBundle('example.com', '2026-05-15T00:00:00Z');
        const signed = signTrustBundle(
            bundle, privateKey, 'auth-2026-05', '2026-05-15T00:00:00Z'
        );

        assert.equal(signed.schemapin_bundle_version, '1.4');
        assert.ok(signed.signature);
        assert.equal(signed.bundle_authority.kid, 'auth-2026-05');
        assert.equal(signed.expires_at, undefined);

        const store = new KeyPinStore();
        assert.equal(verifyTrustBundle(signed, store), true);
    });

    it('tampered bundle fails with SIGNATURE_INVALID', () => {
        const { privateKey } = KeyManager.generateKeypair();
        const bundle = makeBundle('example.com', '2026-05-15T00:00:00Z');
        const signed = signTrustBundle(
            bundle, privateKey, 'auth', '2026-05-15T00:00:00Z'
        );
        signed.documents[0].domain = 'evil.com';

        const store = new KeyPinStore();
        assert.throws(
            () => verifyTrustBundle(signed, store),
            (e) => e.code === ErrorCode.SIGNATURE_INVALID
        );
    });

    it('unsigned bundle rejected with BUNDLE_UNSIGNED', () => {
        const bundle = makeBundle('example.com', '2026-05-15T00:00:00Z');
        const store = new KeyPinStore();
        assert.throws(
            () => verifyTrustBundle(bundle, store),
            (e) => e.code === ErrorCode.BUNDLE_UNSIGNED
        );
    });

    it('expired bundle rejected with BUNDLE_EXPIRED', () => {
        const { privateKey } = KeyManager.generateKeypair();
        const bundle = makeBundle('example.com', '2020-01-01T00:00:00Z');
        const signed = signTrustBundle(
            bundle, privateKey, 'auth', '2020-01-01T00:00:00Z', '2020-02-01T00:00:00Z'
        );
        const store = new KeyPinStore();
        assert.throws(
            () => verifyTrustBundle(signed, store),
            (e) => e.code === ErrorCode.BUNDLE_EXPIRED
        );
    });

    it('authority TOFU mismatch rejected with KEY_PIN_MISMATCH', () => {
        const kp1 = KeyManager.generateKeypair();
        const kp2 = KeyManager.generateKeypair();
        const bundle = makeBundle('example.com', '2026-05-15T00:00:00Z');

        const signed1 = signTrustBundle(
            bundle, kp1.privateKey, 'auth', '2026-05-15T00:00:00Z'
        );
        // Different key, SAME kid -> impersonation attempt.
        const signed2 = signTrustBundle(
            bundle, kp2.privateKey, 'auth', '2026-05-16T00:00:00Z'
        );

        const store = new KeyPinStore();
        assert.equal(verifyTrustBundle(signed1, store), true); // pins kp1
        assert.throws(
            () => verifyTrustBundle(signed2, store),
            (e) => e.code === ErrorCode.KEY_PIN_MISMATCH
        );
    });

    it('merge newest wins (and across domains)', () => {
        const older = makeBundle('example.com', '2026-01-01T00:00:00Z');
        older.documents[0].developer_name = 'Old';
        const newer = makeBundle('example.com', '2026-05-01T00:00:00Z');
        newer.documents[0].developer_name = 'New';
        const other = makeBundle('other.com', '2026-03-01T00:00:00Z');

        const merged = mergeTrustBundles([older, newer, other]);
        assert.equal(merged.schemapin_bundle_version, '1.4');
        assert.equal(merged.documents.length, 2);
        const ex = merged.documents.find((d) => d.domain === 'example.com');
        assert.equal(ex.developer_name, 'New');
        assert.equal(merged.created_at, '2026-05-01T00:00:00Z');
        // Sorted by domain.
        assert.deepEqual(merged.documents.map((d) => d.domain), ['example.com', 'other.com']);
    });

    it('merge: signed_at beats created_at', () => {
        const a = makeBundle('example.com', '2026-01-01T00:00:00Z');
        a.signed_at = '2026-09-01T00:00:00Z';
        a.documents[0].developer_name = 'Signed-late';
        const b = makeBundle('example.com', '2026-06-01T00:00:00Z');
        b.documents[0].developer_name = 'Created-mid';

        const merged = mergeTrustBundles([b, a]);
        assert.equal(merged.documents[0].developer_name, 'Signed-late');
    });

    it('JSON-RPC envelope roundtrip', () => {
        const { privateKey } = KeyManager.generateKeypair();
        const bundle = makeBundle('example.com', '2026-05-15T00:00:00Z');
        const signed = signTrustBundle(
            bundle, privateKey, 'auth', '2026-05-15T00:00:00Z'
        );

        const req = buildTrustBundleRequest('example.com', 1);
        assert.equal(req.method, 'schemapin/trustBundle');
        assert.equal(req.params.domain, 'example.com');

        const reqNoDomain = buildTrustBundleRequest(null, 2);
        assert.deepEqual(reqNoDomain.params, {});

        const resp = buildTrustBundleResponse(signed, 1);
        const parsed = parseTrustBundleResponse(resp);
        assert.deepEqual(parsed, signed);

        const store = new KeyPinStore();
        assert.equal(verifyTrustBundle(parsed, store), true);
    });

    it('parseTrustBundleResponse rejects missing result.bundle', () => {
        assert.throws(
            () => parseTrustBundleResponse({ jsonrpc: '2.0', result: {}, id: 1 }),
            (e) => e.code === ErrorCode.DISCOVERY_INVALID
        );
    });

    it('cross-language fixture verifies (interop proof)', () => {
        const raw = readFileSync(FIXTURE_PATH, 'utf8');
        const bundle = JSON.parse(raw);
        const store = new KeyPinStore();
        assert.equal(verifyTrustBundle(bundle, store), true);
    });
});
