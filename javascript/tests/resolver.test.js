import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
    TrustBundleResolver,
    LocalFileResolver,
    ChainResolver
} from '../src/resolver.js';
import { createTrustBundle, createBundledDiscovery } from '../src/bundle.js';
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

describe('TrustBundleResolver', () => {
    it('should resolve discovery for known domain', async () => {
        const resolver = new TrustBundleResolver(makeBundle());
        const disc = await resolver.resolveDiscovery('example.com');
        assert.ok(disc);
        assert.equal(disc.developer_name, 'Test Dev');
    });

    it('should return null for unknown domain', async () => {
        const resolver = new TrustBundleResolver(makeBundle());
        assert.equal(await resolver.resolveDiscovery('unknown.com'), null);
    });

    it('should resolve revocation for known domain', async () => {
        const resolver = new TrustBundleResolver(makeBundle());
        const disc = await resolver.resolveDiscovery('example.com');
        const rev = await resolver.resolveRevocation('example.com', disc);
        assert.ok(rev);
        assert.equal(rev.domain, 'example.com');
        assert.equal(rev.revoked_keys.length, 1);
    });

    it('should create from JSON', async () => {
        const bundle = makeBundle();
        const json = JSON.stringify(bundle);
        const resolver = TrustBundleResolver.fromJson(json);
        const disc = await resolver.resolveDiscovery('example.com');
        assert.ok(disc);
    });
});

describe('LocalFileResolver', () => {
    it('should resolve discovery from file', async () => {
        const tmpDir = mkdtempSync(join(tmpdir(), 'schemapin-test-'));
        const wellKnown = {
            schema_version: '1.2',
            developer_name: 'File Dev',
            public_key_pem: 'PEM_DATA'
        };
        writeFileSync(join(tmpDir, 'example.com.json'), JSON.stringify(wellKnown));

        const resolver = new LocalFileResolver(tmpDir);
        const disc = await resolver.resolveDiscovery('example.com');
        assert.ok(disc);
        assert.equal(disc.developer_name, 'File Dev');
    });

    it('should return null for missing file', async () => {
        const tmpDir = mkdtempSync(join(tmpdir(), 'schemapin-test-'));
        const resolver = new LocalFileResolver(tmpDir);
        assert.equal(await resolver.resolveDiscovery('missing.com'), null);
    });

    it('should resolve revocation from file', async () => {
        const tmpDir = mkdtempSync(join(tmpdir(), 'schemapin-test-'));
        const rev = buildRevocationDocument('example.com');
        addRevokedKey(rev, 'sha256:bad', RevocationReason.KEY_COMPROMISE);
        writeFileSync(join(tmpDir, 'example.com.revocations.json'), JSON.stringify(rev));

        const resolver = new LocalFileResolver('.', tmpDir);
        const revocation = await resolver.resolveRevocation('example.com', {});
        assert.ok(revocation);
        assert.equal(revocation.domain, 'example.com');
    });

    it('should return null when no revocation dir', async () => {
        const resolver = new LocalFileResolver('.');
        assert.equal(await resolver.resolveRevocation('example.com', {}), null);
    });
});

describe('ChainResolver', () => {
    it('should return first match', async () => {
        const bundle1 = createTrustBundle('2026-01-01T00:00:00Z');
        bundle1.documents.push(createBundledDiscovery('a.com', {
            schema_version: '1.2',
            developer_name: 'First',
            public_key_pem: 'PEM1'
        }));

        const bundle2 = createTrustBundle('2026-01-01T00:00:00Z');
        bundle2.documents.push(createBundledDiscovery('a.com', {
            schema_version: '1.2',
            developer_name: 'Second',
            public_key_pem: 'PEM2'
        }));

        const chain = new ChainResolver([
            new TrustBundleResolver(bundle1),
            new TrustBundleResolver(bundle2)
        ]);
        const disc = await chain.resolveDiscovery('a.com');
        assert.equal(disc.developer_name, 'First');
    });

    it('should fallthrough to second resolver', async () => {
        const bundle1 = createTrustBundle('2026-01-01T00:00:00Z');
        bundle1.documents.push(createBundledDiscovery('a.com', {
            schema_version: '1.2',
            developer_name: 'First',
            public_key_pem: 'PEM1'
        }));

        const bundle2 = createTrustBundle('2026-01-01T00:00:00Z');
        bundle2.documents.push(createBundledDiscovery('b.com', {
            schema_version: '1.2',
            developer_name: 'Second',
            public_key_pem: 'PEM2'
        }));

        const chain = new ChainResolver([
            new TrustBundleResolver(bundle1),
            new TrustBundleResolver(bundle2)
        ]);
        const disc = await chain.resolveDiscovery('b.com');
        assert.ok(disc);
        assert.equal(disc.developer_name, 'Second');
    });

    it('should return null if all miss', async () => {
        const bundle = createTrustBundle('2026-01-01T00:00:00Z');
        const chain = new ChainResolver([new TrustBundleResolver(bundle)]);
        assert.equal(await chain.resolveDiscovery('missing.com'), null);
    });
});
