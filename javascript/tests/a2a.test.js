/**
 * Tests for v1.4 alpha.3 canonicalization id + A2A verification context.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { KeyManager, SignatureManager } from '../src/crypto.js';
import { SchemaPinCore } from '../src/core.js';
import {
    ErrorCode,
    KeyPinStore,
    verifySchemaOffline,
    verifySchemaForA2A,
    checkCanonicalization,
    CANONICALIZATION_V1,
    A2A_MAX_DELEGATION_DEPTH
} from '../src/verification.js';
import {
    A2aVerificationContext,
    a2aAllows,
    a2aIntersect,
    a2aIsUnrestricted
} from '../src/a2a.js';

// ─────────────────────────────────────────────────────────────────────
// AllowedDomains helpers (mirrors AgentPin v0.3 §4.11 semantics)
// ─────────────────────────────────────────────────────────────────────

describe('AllowedDomains helpers', () => {
    it('empty is unrestricted', () => {
        assert.equal(a2aIsUnrestricted([]), true);
        assert.equal(a2aIsUnrestricted(null), true);
        assert.equal(a2aIsUnrestricted(undefined), true);
    });

    it('unrestricted allows anything', () => {
        assert.equal(a2aAllows([], 'literally-anything'), true);
    });

    it('restricted filters', () => {
        const ad = ['api.client.com', '*.partner.com'];
        assert.equal(a2aAllows(ad, 'api.client.com'), true);
        assert.equal(a2aAllows(ad, 'tools.partner.com'), true);
        assert.equal(a2aAllows(ad, 'partner.com'), false); // *.partner.com excludes bare
        assert.equal(a2aAllows(ad, 'evil.example.com'), false);
    });

    it('intersect with unrestricted returns other', () => {
        assert.deepEqual(a2aIntersect([], ['a.com', 'b.com']), ['a.com', 'b.com']);
        assert.deepEqual(a2aIntersect(['a.com', 'b.com'], []), ['a.com', 'b.com']);
    });

    it('intersect returns overlap', () => {
        assert.deepEqual(
            a2aIntersect(['a.com', 'b.com', 'c.com'], ['b.com', 'c.com', 'd.com']),
            ['b.com', 'c.com']
        );
    });

    it('intersect empty overlap is unrestricted per spec', () => {
        const result = a2aIntersect(['a.com'], ['b.com']);
        assert.deepEqual(result, []);
        assert.equal(a2aIsUnrestricted(result), true);
    });
});

// ─────────────────────────────────────────────────────────────────────
// Canonicalization algorithm identifier
// ─────────────────────────────────────────────────────────────────────

describe('checkCanonicalization', () => {
    it('absent is supported', () => {
        assert.equal(checkCanonicalization(null), null);
        assert.equal(checkCanonicalization(undefined), null);
    });

    it('v1 is supported', () => {
        assert.equal(checkCanonicalization(CANONICALIZATION_V1), null);
        assert.equal(checkCanonicalization('schemapin-v1'), null);
    });

    it('unknown returns offending value', () => {
        assert.equal(checkCanonicalization('schemapin-v999'), 'schemapin-v999');
    });
});

// ─────────────────────────────────────────────────────────────────────
// Signed-schema fixture
// ─────────────────────────────────────────────────────────────────────

function setupSchema() {
    const { privateKey, publicKey } = KeyManager.generateKeypair();
    const pubPem = KeyManager.exportPublicKeyPem(publicKey);
    const schema = {
        name: 'calculate_sum',
        description: 'Calculates the sum of two numbers',
        parameters: { a: 'integer', b: 'integer' }
    };
    const schemaHash = SchemaPinCore.canonicalizeAndHash(schema);
    const sig = SignatureManager.signSchemaHash(schemaHash, privateKey);
    return {
        schema,
        sig,
        discovery: {
            schema_version: '1.2',
            developer_name: 'Test Developer',
            public_key_pem: pubPem,
            revoked_keys: []
        }
    };
}

// ─────────────────────────────────────────────────────────────────────
// verifySchemaOffline with canonicalization parameter
// ─────────────────────────────────────────────────────────────────────

describe('verifySchemaOffline canonicalization', () => {
    it('absent canonicalization accepted', () => {
        const f = setupSchema();
        const result = verifySchemaOffline(
            f.schema, f.sig, 'example.com', 'calculate_sum',
            f.discovery, null, new KeyPinStore()
        );
        assert.equal(result.valid, true);
    });

    it('v1 canonicalization accepted', () => {
        const f = setupSchema();
        const result = verifySchemaOffline(
            f.schema, f.sig, 'example.com', 'calculate_sum',
            f.discovery, null, new KeyPinStore(),
            CANONICALIZATION_V1
        );
        assert.equal(result.valid, true);
    });

    it('unknown canonicalization rejected', () => {
        const f = setupSchema();
        const result = verifySchemaOffline(
            f.schema, f.sig, 'example.com', 'calculate_sum',
            f.discovery, null, new KeyPinStore(),
            'schemapin-v999'
        );
        assert.equal(result.valid, false);
        assert.equal(result.error_code, ErrorCode.CANONICALIZATION_UNSUPPORTED);
    });
});

// ─────────────────────────────────────────────────────────────────────
// verifySchemaForA2A
// ─────────────────────────────────────────────────────────────────────

function ctx(trusted, depth = 0) {
    return new A2aVerificationContext({
        callerAgentId: 'urn:agentpin:caller.com:test',
        delegationDepth: depth,
        originatingDomain: 'caller.com',
        trustedDomains: trusted
    });
}

describe('verifySchemaForA2A', () => {
    it('unrestricted caller allows any provider', () => {
        const f = setupSchema();
        const result = verifySchemaForA2A(
            f.schema, f.sig, 'example.com', 'calculate_sum',
            f.discovery, null, new KeyPinStore(),
            ctx([])
        );
        assert.equal(result.valid, true, JSON.stringify(result));
    });

    it('caller allow-list includes provider', () => {
        const f = setupSchema();
        const result = verifySchemaForA2A(
            f.schema, f.sig, 'example.com', 'calculate_sum',
            f.discovery, null, new KeyPinStore(),
            ctx(['example.com', 'other.com'])
        );
        assert.equal(result.valid, true);
    });

    it('provider outside caller scope rejected', () => {
        const f = setupSchema();
        const result = verifySchemaForA2A(
            f.schema, f.sig, 'example.com', 'calculate_sum',
            f.discovery, null, new KeyPinStore(),
            ctx(['other.com'])
        );
        assert.equal(result.valid, false);
        assert.equal(result.error_code, ErrorCode.A2A_SCOPE_VIOLATION);
    });

    it('delegation_depth cap enforced', () => {
        const f = setupSchema();
        const result = verifySchemaForA2A(
            f.schema, f.sig, 'example.com', 'calculate_sum',
            f.discovery, null, new KeyPinStore(),
            ctx([], A2A_MAX_DELEGATION_DEPTH + 1)
        );
        assert.equal(result.valid, false);
        assert.equal(result.error_code, ErrorCode.A2A_SCOPE_VIOLATION);
    });

    it('underlying signature failure passes through', () => {
        const f = setupSchema();
        const result = verifySchemaForA2A(
            f.schema, 'bm90LWEtdmFsaWQtc2lnbmF0dXJl', 'example.com', 'calculate_sum',
            f.discovery, null, new KeyPinStore(),
            ctx([])
        );
        assert.equal(result.valid, false);
        // Underlying error surfaces, not A2A_SCOPE_VIOLATION
        assert.equal(result.error_code, ErrorCode.SIGNATURE_INVALID);
    });

    it('canonicalization unknown rejected through A2A', () => {
        const f = setupSchema();
        const result = verifySchemaForA2A(
            f.schema, f.sig, 'example.com', 'calculate_sum',
            f.discovery, null, new KeyPinStore(),
            ctx([]),
            'schemapin-v999'
        );
        assert.equal(result.valid, false);
        assert.equal(result.error_code, ErrorCode.CANONICALIZATION_UNSUPPORTED);
    });

    it('wildcard provider in caller trusted list', () => {
        const f = setupSchema();
        const result = verifySchemaForA2A(
            f.schema, f.sig, 'api.example.com', 'calculate_sum',
            f.discovery, null, new KeyPinStore(),
            ctx(['*.example.com'])
        );
        assert.equal(result.valid, true, JSON.stringify(result));
    });
});
