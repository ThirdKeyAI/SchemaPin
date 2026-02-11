import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { KeyManager, SignatureManager } from '../src/crypto.js';
import { SchemaPinCore } from '../src/core.js';
import { createTrustBundle, createBundledDiscovery } from '../src/bundle.js';
import { TrustBundleResolver } from '../src/resolver.js';
import {
    buildRevocationDocument,
    addRevokedKey,
    RevocationReason
} from '../src/revocation.js';
import {
    ErrorCode,
    KeyPinStore,
    verifySchemaOffline,
    verifySchemaWithResolver
} from '../src/verification.js';

function makeKeyAndSign(schema) {
    const { privateKey, publicKey } = KeyManager.generateKeypair();
    const pubPem = KeyManager.exportPublicKeyPem(publicKey);
    const schemaHash = SchemaPinCore.canonicalizeAndHash(schema);
    const sig = SignatureManager.signSchemaHash(schemaHash, privateKey);
    const fp = KeyManager.calculateKeyFingerprint(pubPem);
    return { pubPem, sig, fp };
}

describe('KeyPinStore', () => {
    it('should return first_use for new tool@domain', () => {
        const store = new KeyPinStore();
        assert.equal(store.checkAndPin('tool1', 'example.com', 'sha256:aaa'), 'first_use');
    });

    it('should return pinned for same fingerprint', () => {
        const store = new KeyPinStore();
        store.checkAndPin('tool1', 'example.com', 'sha256:aaa');
        assert.equal(store.checkAndPin('tool1', 'example.com', 'sha256:aaa'), 'pinned');
    });

    it('should return changed for different fingerprint', () => {
        const store = new KeyPinStore();
        store.checkAndPin('tool1', 'example.com', 'sha256:aaa');
        assert.equal(store.checkAndPin('tool1', 'example.com', 'sha256:bbb'), 'changed');
    });

    it('should keep different tools independent', () => {
        const store = new KeyPinStore();
        store.checkAndPin('tool1', 'example.com', 'sha256:aaa');
        assert.equal(store.checkAndPin('tool2', 'example.com', 'sha256:bbb'), 'first_use');
    });

    it('should keep different domains independent', () => {
        const store = new KeyPinStore();
        store.checkAndPin('tool1', 'a.com', 'sha256:aaa');
        assert.equal(store.checkAndPin('tool1', 'b.com', 'sha256:bbb'), 'first_use');
    });

    it('should roundtrip through JSON', () => {
        const store = new KeyPinStore();
        store.checkAndPin('tool1', 'example.com', 'sha256:aaa');
        store.checkAndPin('tool2', 'other.com', 'sha256:bbb');

        const json = store.toJSON();
        const restored = KeyPinStore.fromJSON(json);

        assert.equal(restored.checkAndPin('tool1', 'example.com', 'sha256:aaa'), 'pinned');
        assert.equal(restored.checkAndPin('tool2', 'other.com', 'sha256:bbb'), 'pinned');
    });

    it('should get pinned fingerprint', () => {
        const store = new KeyPinStore();
        store.checkAndPin('tool1', 'example.com', 'sha256:aaa');
        assert.equal(store.getPinned('tool1', 'example.com'), 'sha256:aaa');
        assert.equal(store.getPinned('tool2', 'example.com'), null);
    });
});

describe('verifySchemaOffline', () => {
    it('should pass for valid schema and signature', () => {
        const schema = { name: 'test_tool', description: 'A test' };
        const { pubPem, sig } = makeKeyAndSign(schema);

        const discovery = {
            schema_version: '1.2',
            developer_name: 'Test Dev',
            public_key_pem: pubPem
        };
        const store = new KeyPinStore();
        const result = verifySchemaOffline(schema, sig, 'example.com', 'tool1', discovery, null, store);

        assert.equal(result.valid, true);
        assert.equal(result.domain, 'example.com');
        assert.equal(result.developer_name, 'Test Dev');
        assert.equal(result.key_pinning.status, 'first_use');
        assert.equal(result.error_code, undefined);
    });

    it('should return pinned on second call', () => {
        const schema = { name: 'test_tool', description: 'A test' };
        const { pubPem, sig } = makeKeyAndSign(schema);

        const discovery = {
            schema_version: '1.2',
            developer_name: 'Test Dev',
            public_key_pem: pubPem
        };
        const store = new KeyPinStore();
        verifySchemaOffline(schema, sig, 'example.com', 'tool1', discovery, null, store);
        const result = verifySchemaOffline(schema, sig, 'example.com', 'tool1', discovery, null, store);

        assert.equal(result.valid, true);
        assert.equal(result.key_pinning.status, 'pinned');
    });

    it('should fail for invalid signature', () => {
        const schema = { name: 'test_tool', description: 'A test' };
        const { pubPem } = makeKeyAndSign(schema);

        const discovery = {
            schema_version: '1.2',
            developer_name: 'Test Dev',
            public_key_pem: pubPem
        };
        const store = new KeyPinStore();
        const result = verifySchemaOffline(schema, 'invalid_sig', 'example.com', 'tool1', discovery, null, store);

        assert.equal(result.valid, false);
        assert.equal(result.error_code, ErrorCode.SIGNATURE_INVALID);
    });

    it('should fail for tampered schema', () => {
        const schema = { name: 'test_tool', description: 'A test' };
        const { pubPem, sig } = makeKeyAndSign(schema);

        const tampered = { name: 'test_tool', description: 'TAMPERED' };
        const discovery = {
            schema_version: '1.2',
            developer_name: 'Test Dev',
            public_key_pem: pubPem
        };
        const store = new KeyPinStore();
        const result = verifySchemaOffline(tampered, sig, 'example.com', 'tool1', discovery, null, store);

        assert.equal(result.valid, false);
        assert.equal(result.error_code, ErrorCode.SIGNATURE_INVALID);
    });

    it('should fail for revoked key in simple list', () => {
        const schema = { name: 'test_tool', description: 'A test' };
        const { pubPem, sig, fp } = makeKeyAndSign(schema);

        const discovery = {
            schema_version: '1.2',
            developer_name: 'Test Dev',
            public_key_pem: pubPem,
            revoked_keys: [fp]
        };
        const store = new KeyPinStore();
        const result = verifySchemaOffline(schema, sig, 'example.com', 'tool1', discovery, null, store);

        assert.equal(result.valid, false);
        assert.equal(result.error_code, ErrorCode.KEY_REVOKED);
    });

    it('should fail for revoked key in standalone doc', () => {
        const schema = { name: 'test_tool', description: 'A test' };
        const { pubPem, sig, fp } = makeKeyAndSign(schema);

        const discovery = {
            schema_version: '1.2',
            developer_name: 'Test Dev',
            public_key_pem: pubPem
        };
        const rev = buildRevocationDocument('example.com');
        addRevokedKey(rev, fp, RevocationReason.KEY_COMPROMISE);

        const store = new KeyPinStore();
        const result = verifySchemaOffline(schema, sig, 'example.com', 'tool1', discovery, rev, store);

        assert.equal(result.valid, false);
        assert.equal(result.error_code, ErrorCode.KEY_REVOKED);
    });

    it('should reject key pin change', () => {
        const schema = { name: 'test_tool', description: 'A test' };
        const key1 = makeKeyAndSign(schema);
        const key2 = makeKeyAndSign(schema);

        const disc1 = {
            schema_version: '1.2',
            developer_name: 'Dev',
            public_key_pem: key1.pubPem
        };
        const disc2 = {
            schema_version: '1.2',
            developer_name: 'Dev',
            public_key_pem: key2.pubPem
        };

        const store = new KeyPinStore();
        const r1 = verifySchemaOffline(schema, key1.sig, 'example.com', 'tool1', disc1, null, store);
        assert.equal(r1.valid, true);

        const r2 = verifySchemaOffline(schema, key2.sig, 'example.com', 'tool1', disc2, null, store);
        assert.equal(r2.valid, false);
        assert.equal(r2.error_code, ErrorCode.KEY_PIN_MISMATCH);
    });

    it('should fail for invalid discovery', () => {
        const store = new KeyPinStore();
        const result = verifySchemaOffline(
            { name: 'test' }, 'sig', 'example.com', 'tool1',
            { schema_version: '1.2' }, null, store
        );
        assert.equal(result.valid, false);
        assert.equal(result.error_code, ErrorCode.DISCOVERY_INVALID);
    });

    it('should fail for empty discovery', () => {
        const store = new KeyPinStore();
        const result = verifySchemaOffline(
            { name: 'test' }, 'sig', 'example.com', 'tool1',
            {}, null, store
        );
        assert.equal(result.valid, false);
        assert.equal(result.error_code, ErrorCode.DISCOVERY_INVALID);
    });
});

describe('verifySchemaWithResolver', () => {
    it('should pass with TrustBundleResolver', async () => {
        const schema = { name: 'test_tool', description: 'A test' };
        const { pubPem, sig } = makeKeyAndSign(schema);

        const wellKnown = {
            schema_version: '1.2',
            developer_name: 'Bundle Dev',
            public_key_pem: pubPem
        };
        const doc = createBundledDiscovery('example.com', wellKnown);
        const bundle = createTrustBundle('2026-01-01T00:00:00Z');
        bundle.documents.push(doc);

        const resolver = new TrustBundleResolver(bundle);
        const store = new KeyPinStore();

        const result = await verifySchemaWithResolver(schema, sig, 'example.com', 'tool1', resolver, store);
        assert.equal(result.valid, true);
        assert.equal(result.developer_name, 'Bundle Dev');
    });

    it('should fail for missing domain', async () => {
        const bundle = createTrustBundle('2026-01-01T00:00:00Z');
        const resolver = new TrustBundleResolver(bundle);
        const store = new KeyPinStore();

        const result = await verifySchemaWithResolver(
            { name: 'test' }, 'sig', 'missing.com', 'tool1', resolver, store
        );
        assert.equal(result.valid, false);
        assert.equal(result.error_code, ErrorCode.DISCOVERY_FETCH_FAILED);
    });
});
