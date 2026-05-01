/**
 * Tests for DNS TXT cross-verification (v1.4).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { KeyManager } from '../src/crypto.js';
import { parseTxtRecord, verifyDnsMatch, txtRecordName } from '../src/dns.js';

// ---------------------------------------------------------------------------
// parseTxtRecord
// ---------------------------------------------------------------------------

describe('parseTxtRecord', () => {
    it('should parse a full record', () => {
        const r = parseTxtRecord('v=schemapin1; kid=acme-2026-01; fp=sha256:abcd1234');
        assert.equal(r.version, 'schemapin1');
        assert.equal(r.kid, 'acme-2026-01');
        assert.equal(r.fingerprint, 'sha256:abcd1234');
    });

    it('should parse a minimal record (no kid)', () => {
        const r = parseTxtRecord('v=schemapin1;fp=sha256:abc');
        assert.equal(r.version, 'schemapin1');
        assert.equal(r.kid, null);
        assert.equal(r.fingerprint, 'sha256:abc');
    });

    it('should lowercase the fingerprint', () => {
        const r = parseTxtRecord('v=schemapin1; fp=SHA256:ABCDEF');
        assert.equal(r.fingerprint, 'sha256:abcdef');
    });

    it('should tolerate whitespace and field order', () => {
        const r = parseTxtRecord('  fp = sha256:beef ;  v = schemapin1  ');
        assert.equal(r.version, 'schemapin1');
        assert.equal(r.fingerprint, 'sha256:beef');
    });

    it('should ignore unknown fields (forward-compat)', () => {
        const r = parseTxtRecord('v=schemapin1; fp=sha256:abc; future=ignoreme');
        assert.equal(r.fingerprint, 'sha256:abc');
        assert.equal(r.version, 'schemapin1');
    });

    it('should reject when v is missing', () => {
        assert.throws(() => parseTxtRecord('fp=sha256:abc'), /missing required 'v'/);
    });

    it('should reject when fp is missing', () => {
        assert.throws(() => parseTxtRecord('v=schemapin1'), /missing required 'fp'/);
    });

    it('should reject unsupported version', () => {
        assert.throws(
            () => parseTxtRecord('v=schemapin99; fp=sha256:abc'),
            /unsupported version/
        );
    });

    it('should reject fp without sha256: prefix', () => {
        assert.throws(
            () => parseTxtRecord('v=schemapin1; fp=abc'),
            /must be sha256/
        );
    });

    it('should reject a field that has no = sign', () => {
        assert.throws(
            () => parseTxtRecord('v=schemapin1; broken'),
            /missing '='/
        );
    });

    it('should tolerate a trailing semicolon', () => {
        const r = parseTxtRecord('v=schemapin1; fp=sha256:abc;');
        assert.equal(r.fingerprint, 'sha256:abc');
    });
});

// ---------------------------------------------------------------------------
// txtRecordName
// ---------------------------------------------------------------------------

describe('txtRecordName', () => {
    it('should prefix _schemapin', () => {
        assert.equal(txtRecordName('example.com'), '_schemapin.example.com');
    });

    it('should strip a trailing dot from the domain', () => {
        assert.equal(txtRecordName('example.com.'), '_schemapin.example.com');
    });
});

// ---------------------------------------------------------------------------
// verifyDnsMatch
// ---------------------------------------------------------------------------

describe('verifyDnsMatch', () => {
    function makeDiscovery(publicKeyPem) {
        return {
            schema_version: '1.4',
            developer_name: 'Dev',
            public_key_pem: publicKeyPem
        };
    }

    it('should accept a matching fingerprint', () => {
        const { publicKey } = KeyManager.generateKeypair();
        const fp = KeyManager.calculateKeyFingerprint(publicKey).toLowerCase();
        const txt = { version: 'schemapin1', kid: null, fingerprint: fp };
        // Should not throw
        verifyDnsMatch(makeDiscovery(publicKey), txt);
    });

    it('should accept a matching fingerprint case-insensitively', () => {
        const { publicKey } = KeyManager.generateKeypair();
        const fp = KeyManager.calculateKeyFingerprint(publicKey).toUpperCase();
        // Mimic parser output: parser lowercases everything.
        const txt = { version: 'schemapin1', kid: null, fingerprint: fp.toLowerCase() };
        verifyDnsMatch(makeDiscovery(publicKey), txt);
    });

    it('should throw on fingerprint mismatch', () => {
        const { publicKey } = KeyManager.generateKeypair();
        const txt = {
            version: 'schemapin1',
            kid: null,
            fingerprint: 'sha256:0000000000000000000000000000000000000000000000000000000000000000'
        };
        assert.throws(() => verifyDnsMatch(makeDiscovery(publicKey), txt), /mismatch/);
    });

    it('should throw when discovery is missing public_key_pem', () => {
        const txt = {
            version: 'schemapin1',
            kid: null,
            fingerprint: 'sha256:abc'
        };
        assert.throws(() => verifyDnsMatch({}, txt), /missing public_key_pem/);
    });
});
