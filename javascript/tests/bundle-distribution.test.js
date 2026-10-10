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
    seedBundleAuthority,
    seedBundleAuthorityFromPem,
    BUNDLE_AUTHORITY_PIN_DOMAIN,
    mergeTrustBundles,
    buildTrustBundleRequest,
    buildTrustBundleResponse,
    parseTrustBundleResponse,
    createTrustBundle,
    createBundledDiscovery
} from '../src/bundle.js';
import { ErrorCode, KeyPinStore } from '../src/verification.js';
import { TrustBundleResolver } from '../src/resolver.js';
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
        assert.equal(verifyTrustBundle(signed, store, true).first_use, true);
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
            () => verifyTrustBundle(signed, store, true),
            (e) => e.code === ErrorCode.SIGNATURE_INVALID
        );
    });

    it('unsigned bundle rejected with BUNDLE_UNSIGNED', () => {
        const bundle = makeBundle('example.com', '2026-05-15T00:00:00Z');
        const store = new KeyPinStore();
        assert.throws(
            () => verifyTrustBundle(bundle, store, true),
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
            () => verifyTrustBundle(signed, store, true),
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
        assert.equal(verifyTrustBundle(signed1, store, true).first_use, true); // pins kp1
        assert.throws(
            () => verifyTrustBundle(signed2, store, true),
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
        assert.equal(verifyTrustBundle(parsed, store, true).first_use, true);
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
        assert.equal(bundle.bundle_authority.kid, 'schemapin-test-fixture-authority');
        // Unknown authority: refused unless seeded.
        assert.throws(
            () => verifyTrustBundle(bundle, new KeyPinStore()),
            (e) => e.code === ErrorCode.BUNDLE_AUTHORITY_UNTRUSTED
        );
        const store = new KeyPinStore();
        const pub = readFileSync(resolve(REPO_ROOT, 'tests', 'cross-language', 'keys', 'test-only-bundle-authority.pub.pem'), 'utf8');
        seedBundleAuthorityFromPem(store, bundle.bundle_authority.kid, pub);
        assert.equal(verifyTrustBundle(bundle, store).first_use, false);
        // A different seeded key is an impersonation.
        const other = new KeyPinStore();
        seedBundleAuthority(other, bundle.bundle_authority.kid, 'sha256:' + '00'.repeat(32));
        assert.throws(() => verifyTrustBundle(bundle, other), (e) => e.code === ErrorCode.KEY_PIN_MISMATCH);
    });
});

describe('authority allow-list (SP-6)', () => {
    it('refuses a self-signed bundle under a fresh kid', () => {
        const { privateKey } = KeyManager.generateKeypair();
        const signed = signTrustBundle(makeBundle('victim.com', '2026-05-15T00:00:00Z'), privateKey, 'victim-authority-2026', '2026-05-15T00:00:00Z');
        assert.throws(() => verifyTrustBundle(signed, new KeyPinStore()), (e) => e.code === ErrorCode.BUNDLE_AUTHORITY_UNTRUSTED);
    });

    it('seeded authority passes strictly; first use is reported and pinned', () => {
        const { privateKey } = KeyManager.generateKeypair();
        const signed = signTrustBundle(makeBundle('example.com', '2026-05-15T00:00:00Z'), privateKey, 'auth', '2026-05-15T00:00:00Z');
        const store = new KeyPinStore();
        const fp = seedBundleAuthorityFromPem(store, 'auth', signed.bundle_authority.public_key_pem);
        const r = verifyTrustBundle(signed, store);
        assert.equal(r.first_use, false);
        assert.equal(r.fingerprint, fp);
        const fresh = new KeyPinStore();
        assert.equal(verifyTrustBundle(signed, fresh, true).first_use, true);
        assert.equal(verifyTrustBundle(signed, fresh).first_use, false);
    });

    it('a failed signature never pins the authority', () => {
        const { privateKey } = KeyManager.generateKeypair();
        const signed = signTrustBundle(makeBundle('example.com', '2026-05-15T00:00:00Z'), privateKey, 'auth', '2026-05-15T00:00:00Z');
        signed.documents[0].domain = 'evil.com';
        const store = new KeyPinStore();
        assert.throws(() => verifyTrustBundle(signed, store, true), (e) => e.code === ErrorCode.SIGNATURE_INVALID);
        assert.equal(store.getPinned('auth', BUNDLE_AUTHORITY_PIN_DOMAIN), null);
    });
});

describe('parity (SP-19)', () => {
    it('rejects lenient date strings for expires_at', () => {
        const { privateKey } = KeyManager.generateKeypair();
        for (const bad of ['2099-01-01', '2099-01-01T00:00:00', '2099-01-01 00:00:00Z']) {
            const signed = signTrustBundle(makeBundle('example.com', '2026-05-15T00:00:00Z'), privateKey, 'auth', '2026-05-15T00:00:00Z', bad);
            assert.throws(() => verifyTrustBundle(signed, new KeyPinStore(), true), (e) => e.code === ErrorCode.BUNDLE_EXPIRED, bad);
        }
    });

    it('unknown fields are not part of the signing input', () => {
        const { privateKey } = KeyManager.generateKeypair();
        const bundle = makeBundle('example.com', '2026-05-15T00:00:00Z');
        bundle['x-extra'] = 'ignored';
        bundle.documents[0]['x-extra'] = 'ignored';
        const signed = signTrustBundle(bundle, privateKey, 'auth', '2026-05-15T00:00:00Z');
        delete signed['x-extra'];
        delete signed.documents[0]['x-extra'];
        assert.equal(verifyTrustBundle(signed, new KeyPinStore(), true).kid, 'auth');
        const b2 = makeBundle('example.com', '2026-05-15T00:00:00Z');
        delete b2.documents[0].revoked_keys;
        const s2 = signTrustBundle(b2, privateKey, 'auth', '2026-05-15T00:00:00Z');
        s2.documents[0].revoked_keys = [];
        assert.equal(verifyTrustBundle(s2, new KeyPinStore(), true).kid, 'auth');
    });

    it('rejects duplicate domains', () => {
        const { privateKey } = KeyManager.generateKeypair();
        const bundle = makeBundle('example.com', '2026-05-15T00:00:00Z');
        bundle.documents.push({ ...bundle.documents[0] });
        assert.throws(() => signTrustBundle(bundle, privateKey, 'auth', '2026-05-15T00:00:00Z'), /duplicate/);
        assert.throws(() => new TrustBundleResolver(bundle), /duplicate/);
    });
});

describe('merge precedence (design 4)', () => {
    function named(name, createdAt) {
        const b = makeBundle('example.com', createdAt);
        b.documents[0].developer_name = name;
        return b;
    }

    it('authority precedence beats timestamp; parsed timestamps break ties', () => {
        const trusted = KeyManager.generateKeypair().privateKey;
        const rogue = KeyManager.generateKeypair().privateKey;
        const good = signTrustBundle(named('Good', '2026-01-01T00:00:00Z'), trusted, 'trusted', '2026-01-01T00:00:00Z');
        const bad = signTrustBundle(named('Rogue', '2099-01-01T00:00:00Z'), rogue, 'rogue', '2099-01-01T00:00:00Z');
        assert.equal(mergeTrustBundles([bad, good], ['trusted']).documents[0].developer_name, 'Good');
        assert.equal(mergeTrustBundles([good, bad]).documents[0].developer_name, 'Rogue');
        const real = named('Real', '2026-01-01T00:00:00Z');
        const bogus = named('Bogus', '9999-99-99 bogus');
        assert.equal(mergeTrustBundles([real, bogus]).documents[0].developer_name, 'Real');
        const offset = named('Offset', '2026-02-01T00:00:00+00:00');
        assert.equal(mergeTrustBundles([real, offset]).documents[0].developer_name, 'Offset');
    });
});
