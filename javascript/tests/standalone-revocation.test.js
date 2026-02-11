import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
    RevocationReason,
    buildRevocationDocument,
    addRevokedKey,
    checkRevocation,
    checkRevocationCombined
} from '../src/revocation.js';

describe('RevocationDocument', () => {
    it('should build an empty revocation document', () => {
        const doc = buildRevocationDocument('example.com');
        assert.equal(doc.domain, 'example.com');
        assert.equal(doc.schemapin_version, '1.2');
        assert.deepEqual(doc.revoked_keys, []);
        assert.ok(doc.updated_at);
    });

    it('should add a revoked key', () => {
        const doc = buildRevocationDocument('example.com');
        addRevokedKey(doc, 'sha256:abc123', RevocationReason.KEY_COMPROMISE);
        assert.equal(doc.revoked_keys.length, 1);
        assert.equal(doc.revoked_keys[0].fingerprint, 'sha256:abc123');
        assert.equal(doc.revoked_keys[0].reason, 'key_compromise');
    });

    it('should add multiple revoked keys', () => {
        const doc = buildRevocationDocument('example.com');
        addRevokedKey(doc, 'sha256:aaa', RevocationReason.KEY_COMPROMISE);
        addRevokedKey(doc, 'sha256:bbb', RevocationReason.SUPERSEDED);
        addRevokedKey(doc, 'sha256:ccc', RevocationReason.CESSATION_OF_OPERATION);
        assert.equal(doc.revoked_keys.length, 3);
    });

    it('should not throw for non-revoked fingerprint', () => {
        const doc = buildRevocationDocument('example.com');
        addRevokedKey(doc, 'sha256:abc123', RevocationReason.KEY_COMPROMISE);
        assert.doesNotThrow(() => checkRevocation(doc, 'sha256:other'));
    });

    it('should throw for revoked fingerprint', () => {
        const doc = buildRevocationDocument('example.com');
        addRevokedKey(doc, 'sha256:abc123', RevocationReason.KEY_COMPROMISE);
        assert.throws(() => checkRevocation(doc, 'sha256:abc123'), /revoked/);
    });

    it('should not throw for empty document', () => {
        const doc = buildRevocationDocument('example.com');
        assert.doesNotThrow(() => checkRevocation(doc, 'sha256:anything'));
    });
});

describe('checkRevocationCombined', () => {
    it('should catch revocation in simple list', () => {
        assert.throws(
            () => checkRevocationCombined(['sha256:abc123'], null, 'sha256:abc123'),
            /simple revocation list/
        );
    });

    it('should catch revocation in standalone doc', () => {
        const doc = buildRevocationDocument('example.com');
        addRevokedKey(doc, 'sha256:abc123', RevocationReason.SUPERSEDED);
        assert.throws(
            () => checkRevocationCombined([], doc, 'sha256:abc123'),
            /revoked/
        );
    });

    it('should pass for clean key', () => {
        const doc = buildRevocationDocument('example.com');
        addRevokedKey(doc, 'sha256:other', RevocationReason.SUPERSEDED);
        assert.doesNotThrow(() => checkRevocationCombined(['sha256:other2'], doc, 'sha256:clean'));
    });

    it('should handle null inputs', () => {
        assert.doesNotThrow(() => checkRevocationCombined(null, null, 'sha256:anything'));
    });
});

describe('RevocationReason', () => {
    it('should have correct values', () => {
        assert.equal(RevocationReason.KEY_COMPROMISE, 'key_compromise');
        assert.equal(RevocationReason.SUPERSEDED, 'superseded');
        assert.equal(RevocationReason.CESSATION_OF_OPERATION, 'cessation_of_operation');
        assert.equal(RevocationReason.PRIVILEGE_WITHDRAWN, 'privilege_withdrawn');
    });
});

describe('Serialization', () => {
    it('should roundtrip through JSON', () => {
        const doc = buildRevocationDocument('example.com');
        addRevokedKey(doc, 'sha256:aaa', RevocationReason.KEY_COMPROMISE);
        addRevokedKey(doc, 'sha256:bbb', RevocationReason.SUPERSEDED);

        const json = JSON.stringify(doc);
        const restored = JSON.parse(json);

        assert.equal(restored.domain, 'example.com');
        assert.equal(restored.schemapin_version, '1.2');
        assert.equal(restored.revoked_keys.length, 2);
        assert.equal(restored.revoked_keys[0].fingerprint, 'sha256:aaa');
        assert.equal(restored.revoked_keys[1].reason, 'superseded');
    });
});
