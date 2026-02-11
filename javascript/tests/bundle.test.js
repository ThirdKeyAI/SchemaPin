import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
    createTrustBundle,
    createBundledDiscovery,
    findDiscovery,
    findRevocation,
    parseTrustBundle
} from '../src/bundle.js';
import {
    buildRevocationDocument,
    addRevokedKey,
    RevocationReason
} from '../src/revocation.js';

function makeBundle() {
    const wellKnown = {
        schema_version: '1.2',
        developer_name: 'Test Dev',
        public_key_pem: '-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----'
    };
    const doc = createBundledDiscovery('example.com', wellKnown);
    const rev = buildRevocationDocument('example.com');
    addRevokedKey(rev, 'sha256:old', RevocationReason.SUPERSEDED);

    const bundle = createTrustBundle('2026-01-01T00:00:00Z');
    bundle.documents.push(doc);
    bundle.revocations.push(rev);
    return bundle;
}

describe('TrustBundle', () => {
    it('should create a bundle', () => {
        const bundle = makeBundle();
        assert.equal(bundle.schemapin_bundle_version, '1.2');
        assert.equal(bundle.documents.length, 1);
        assert.equal(bundle.revocations.length, 1);
    });

    it('should find discovery for known domain', () => {
        const bundle = makeBundle();
        const disc = findDiscovery(bundle, 'example.com');
        assert.ok(disc);
        assert.equal(disc.developer_name, 'Test Dev');
        assert.ok(disc.public_key_pem.startsWith('-----BEGIN PUBLIC KEY-----'));
        assert.equal(disc.domain, undefined);
    });

    it('should return null for unknown domain', () => {
        const bundle = makeBundle();
        assert.equal(findDiscovery(bundle, 'unknown.com'), null);
    });

    it('should find revocation for known domain', () => {
        const bundle = makeBundle();
        const rev = findRevocation(bundle, 'example.com');
        assert.ok(rev);
        assert.equal(rev.domain, 'example.com');
        assert.equal(rev.revoked_keys.length, 1);
    });

    it('should return null for unknown domain revocation', () => {
        const bundle = makeBundle();
        assert.equal(findRevocation(bundle, 'unknown.com'), null);
    });

    it('should roundtrip through JSON', () => {
        const bundle = makeBundle();
        const json = JSON.stringify(bundle);
        const restored = parseTrustBundle(json);

        assert.equal(restored.schemapin_bundle_version, '1.2');
        assert.equal(restored.documents.length, 1);
        assert.equal(restored.revocations.length, 1);
        assert.equal(restored.documents[0].domain, 'example.com');
        assert.equal(restored.revocations[0].domain, 'example.com');
    });

    it('should use flattened format', () => {
        const wellKnown = {
            schema_version: '1.2',
            developer_name: 'Dev',
            public_key_pem: 'PEM',
            contact: 'dev@example.com'
        };
        const entry = createBundledDiscovery('example.com', wellKnown);

        assert.equal(entry.domain, 'example.com');
        assert.equal(entry.schema_version, '1.2');
        assert.equal(entry.developer_name, 'Dev');
        assert.equal(entry.public_key_pem, 'PEM');
        assert.equal(entry.contact, 'dev@example.com');
    });

    it('should handle empty bundle', () => {
        const bundle = createTrustBundle('2026-01-01T00:00:00Z');
        assert.equal(findDiscovery(bundle, 'example.com'), null);
        assert.equal(findRevocation(bundle, 'example.com'), null);
    });
});
