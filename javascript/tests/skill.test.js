/**
 * Tests for skill folder signing and verification.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import * as nodeCrypto from 'node:crypto';
import { KeyManager } from '../src/crypto.js';
import { buildRevocationDocument, addRevokedKey, RevocationReason } from '../src/revocation.js';
import { ErrorCode, KeyPinStore, applyExpirationCheck } from '../src/verification.js';
import { SchemaResolver } from '../src/resolver.js';
import { KeyManager as KM, SignatureManager } from '../src/crypto.js';
import { symlinkSync } from 'node:fs';
import {
    SIGNATURE_FILENAME, canonicalizeSkill, canonicalizeSkillV1, parseSkillName, loadSignature,
    signSkill, signSkillWithOptions, verifySkillOffline, verifySkillOfflineWithDns,
    verifySkillWithResolver, detectTamperedFiles, verifyChain, ChainError,
    SkillCanonicalizationError
} from '../src/skill.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeKeypair() {
    const { privateKey, publicKey } = KeyManager.generateKeypair();
    return { privateKey, publicKey };
}

function createSkillDir(basePath, files) {
    mkdirSync(basePath, { recursive: true });
    for (const [relPath, content] of Object.entries(files)) {
        const fullPath = join(basePath, ...relPath.split('/'));
        mkdirSync(join(fullPath, '..'), { recursive: true });
        if (typeof content === 'string') {
            writeFileSync(fullPath, content, 'utf-8');
        } else {
            writeFileSync(fullPath, content);
        }
    }
    return basePath;
}

function makeDiscovery(publicKeyPem) {
    return {
        schema_version: '1.3',
        developer_name: 'Test Dev',
        public_key_pem: publicKeyPem
    };
}

// ---------------------------------------------------------------------------
// Canonicalization
// ---------------------------------------------------------------------------

describe('Canonicalization', () => {
    it('should produce sorted deterministic results', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            createSkillDir(dir, { 'b.txt': 'B', 'a.txt': 'A', 'c.txt': 'C' });
            const { rootHash: h1, manifest: m1 } = canonicalizeSkill(dir);
            const { rootHash: h2, manifest: m2 } = canonicalizeSkill(dir);
            assert.deepEqual(h1, h2);
            assert.deepEqual(m1, m2);
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('should skip .schemapin.sig', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            createSkillDir(dir, {
                'SKILL.md': '# hi',
                [SIGNATURE_FILENAME]: 'ignored'
            });
            const { manifest } = canonicalizeSkill(dir);
            assert.ok(!(SIGNATURE_FILENAME in manifest));
            assert.ok('SKILL.md' in manifest);
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('should handle nested directories', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            createSkillDir(dir, {
                'SKILL.md': '# hi',
                'sub/nested.txt': 'deep'
            });
            const { manifest } = canonicalizeSkill(dir);
            assert.ok('sub/nested.txt' in manifest);
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('should use forward slashes in all manifest keys', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            createSkillDir(dir, { 'a/b/c.txt': 'content' });
            const { manifest } = canonicalizeSkill(dir);
            for (const key of Object.keys(manifest)) {
                assert.ok(!key.includes('\\'), `Key "${key}" contains backslash`);
            }
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('should throw for empty directory', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            mkdirSync(join(dir, 'empty'), { recursive: true });
            assert.throws(
                () => canonicalizeSkill(join(dir, 'empty')),
                /empty/
            );
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('should hash binary files correctly', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            createSkillDir(dir, {
                'SKILL.md': '# ok',
                'data.bin': Buffer.from([0x00, 0x01, 0x02, 0xff])
            });
            const { manifest } = canonicalizeSkill(dir);
            assert.ok('data.bin' in manifest);
            assert.ok(manifest['data.bin'].startsWith('sha256:'));
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('should produce different hashes for different content', () => {
        const d1 = mkdtempSync(join(tmpdir(), 'skill-test-'));
        const d2 = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            createSkillDir(d1, { 'a.txt': 'v1' });
            createSkillDir(d2, { 'a.txt': 'v2' });
            const { rootHash: h1 } = canonicalizeSkill(d1);
            const { rootHash: h2 } = canonicalizeSkill(d2);
            assert.notDeepEqual(h1, h2);
        } finally {
            rmSync(d1, { recursive: true, force: true });
            rmSync(d2, { recursive: true, force: true });
        }
    });
});

// ---------------------------------------------------------------------------
// File Manifest
// ---------------------------------------------------------------------------

describe('File Manifest', () => {
    it('should include all non-sig files', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            createSkillDir(dir, {
                'SKILL.md': '# hi',
                'index.py': 'pass',
                'lib/util.py': 'x=1'
            });
            const { manifest } = canonicalizeSkill(dir);
            assert.deepEqual(
                new Set(Object.keys(manifest)),
                new Set(['SKILL.md', 'index.py', 'lib/util.py'])
            );
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('should use sha256: format for all values', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            createSkillDir(dir, { 'a.txt': 'hello', 'b.txt': 'world' });
            const { manifest } = canonicalizeSkill(dir);
            for (const val of Object.values(manifest)) {
                assert.ok(val.startsWith('sha256:'));
                const hex = val.split(':')[1];
                assert.equal(hex.length, 64);
            }
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('should exclude the signature file', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            createSkillDir(dir, {
                'SKILL.md': '# hi',
                [SIGNATURE_FILENAME]: '{"sig": true}'
            });
            const { manifest } = canonicalizeSkill(dir);
            assert.ok(!(SIGNATURE_FILENAME in manifest));
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });
});

// ---------------------------------------------------------------------------
// Parse Skill Name
// ---------------------------------------------------------------------------

describe('Parse Skill Name', () => {
    it('should extract name from frontmatter', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const skillDir = join(dir, 'my-skill');
            createSkillDir(skillDir, {
                'SKILL.md': '---\nname: cool-skill\n---\n# Hello'
            });
            assert.equal(parseSkillName(skillDir), 'cool-skill');
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('should handle quoted name values', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const skillDir = join(dir, 'skill');
            createSkillDir(skillDir, {
                'SKILL.md': '---\nname: \'quoted-name\'\n---\n# Hello'
            });
            assert.equal(parseSkillName(skillDir), 'quoted-name');
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('should handle double-quoted name values', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const skillDir = join(dir, 'skill');
            createSkillDir(skillDir, {
                'SKILL.md': '---\nname: "dq-name"\n---\n# Hello'
            });
            assert.equal(parseSkillName(skillDir), 'dq-name');
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('should fallback to dirname when no frontmatter', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const skillDir = join(dir, 'fallback-dir');
            createSkillDir(skillDir, {
                'SKILL.md': '# Just markdown, no frontmatter'
            });
            assert.equal(parseSkillName(skillDir), 'fallback-dir');
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('should fallback to dirname when no SKILL.md', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const skillDir = join(dir, 'dirname-skill');
            createSkillDir(skillDir, { 'index.py': 'pass' });
            assert.equal(parseSkillName(skillDir), 'dirname-skill');
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });
});

// ---------------------------------------------------------------------------
// Sign and Verify
// ---------------------------------------------------------------------------

describe('Sign and Verify', () => {
    it('should create signature file', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const { privateKey } = makeKeypair();
            const skillDir = join(dir, 'skill');
            createSkillDir(skillDir, {
                'SKILL.md': '---\nname: test-skill\n---\n# Hello'
            });
            signSkill(skillDir, privateKey, 'example.com');
            const sigPath = join(skillDir, SIGNATURE_FILENAME);
            const content = readFileSync(sigPath, 'utf-8');
            assert.ok(content.length > 0);
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('should produce correct signature structure', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const { privateKey } = makeKeypair();
            const skillDir = join(dir, 'skill');
            createSkillDir(skillDir, {
                'SKILL.md': '---\nname: test-skill\n---\n# Hello'
            });
            const sig = signSkill(skillDir, privateKey, 'example.com');
            assert.equal(sig.schemapin_version, '1.4');
            assert.equal(sig.skill_name, 'test-skill');
            assert.ok(sig.skill_hash.startsWith('sha256:'));
            assert.equal(typeof sig.signature, 'string');
            assert.equal(sig.domain, 'example.com');
            assert.ok(sig.signer_kid.startsWith('sha256:'));
            assert.ok('file_manifest' in sig);
            assert.ok('SKILL.md' in sig.file_manifest);
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('should roundtrip sign and verify', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const { privateKey, publicKey } = makeKeypair();
            const skillDir = join(dir, 'skill');
            createSkillDir(skillDir, {
                'SKILL.md': '---\nname: roundtrip\n---\n# ok',
                'lib.py': 'x=1'
            });
            signSkill(skillDir, privateKey, 'example.com');
            const result = verifySkillOffline(skillDir, makeDiscovery(publicKey));
            assert.equal(result.valid, true);
            assert.equal(result.domain, 'example.com');
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('should fail with wrong key', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const key1 = makeKeypair();
            const key2 = makeKeypair();
            const skillDir = join(dir, 'skill');
            createSkillDir(skillDir, { 'SKILL.md': '# hi' });
            signSkill(skillDir, key1.privateKey, 'example.com');
            const result = verifySkillOffline(skillDir, makeDiscovery(key2.publicKey));
            assert.equal(result.valid, false);
            assert.equal(result.error_code, ErrorCode.SIGNATURE_INVALID);
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('should fail when file is tampered', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const { privateKey, publicKey } = makeKeypair();
            const skillDir = join(dir, 'skill');
            createSkillDir(skillDir, { 'SKILL.md': '# original' });
            signSkill(skillDir, privateKey, 'example.com');
            writeFileSync(join(skillDir, 'SKILL.md'), '# TAMPERED', 'utf-8');
            const result = verifySkillOffline(skillDir, makeDiscovery(publicKey));
            assert.equal(result.valid, false);
            assert.equal(result.error_code, ErrorCode.SIGNATURE_INVALID);
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('should use custom name and kid', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const { privateKey } = makeKeypair();
            const skillDir = join(dir, 'skill');
            createSkillDir(skillDir, {
                'SKILL.md': '---\nname: original\n---\n# hi'
            });
            const sig = signSkill(skillDir, privateKey, 'example.com', 'sha256:custom', 'override');
            assert.equal(sig.skill_name, 'override');
            assert.equal(sig.signer_kid, 'sha256:custom');
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });
});

// ---------------------------------------------------------------------------
// Verify Offline
// ---------------------------------------------------------------------------

describe('Verify Offline', () => {
    it('should succeed with pinning on happy path', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const { privateKey, publicKey } = makeKeypair();
            const skillDir = join(dir, 'skill');
            createSkillDir(skillDir, {
                'SKILL.md': '---\nname: test\n---\n# ok'
            });
            signSkill(skillDir, privateKey, 'example.com');
            const store = new KeyPinStore();
            const result = verifySkillOffline(
                skillDir, makeDiscovery(publicKey), null, null, store, 'test'
            );
            assert.equal(result.valid, true);
            assert.ok(result.key_pinning !== null);
            assert.equal(result.key_pinning.status, 'first_use');
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('should fail for revoked key', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const { privateKey, publicKey } = makeKeypair();
            const fp = KeyManager.calculateKeyFingerprint(publicKey);
            const skillDir = join(dir, 'skill');
            createSkillDir(skillDir, { 'SKILL.md': '# hi' });
            signSkill(skillDir, privateKey, 'example.com');
            const rev = buildRevocationDocument('example.com');
            addRevokedKey(rev, fp, RevocationReason.KEY_COMPROMISE);
            const result = verifySkillOffline(
                skillDir, makeDiscovery(publicKey), null, rev
            );
            assert.equal(result.valid, false);
            assert.equal(result.error_code, ErrorCode.KEY_REVOKED);
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('should reject key pin mismatch', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const key1 = makeKeypair();
            const key2 = makeKeypair();
            const skillDir = join(dir, 'skill');
            createSkillDir(skillDir, { 'SKILL.md': '# hi' });

            // Sign with key 1, pin it
            signSkill(skillDir, key1.privateKey, 'example.com');
            const store = new KeyPinStore();
            const r1 = verifySkillOffline(
                skillDir, makeDiscovery(key1.publicKey), null, null, store, 't'
            );
            assert.equal(r1.valid, true);

            // Re-sign with key 2
            signSkill(skillDir, key2.privateKey, 'example.com');
            const r2 = verifySkillOffline(
                skillDir, makeDiscovery(key2.publicKey), null, null, store, 't'
            );
            assert.equal(r2.valid, false);
            assert.equal(r2.error_code, ErrorCode.KEY_PIN_MISMATCH);
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('should fail for invalid discovery', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const { privateKey } = makeKeypair();
            const skillDir = join(dir, 'skill');
            createSkillDir(skillDir, { 'SKILL.md': '# hi' });
            signSkill(skillDir, privateKey, 'example.com');
            const result = verifySkillOffline(
                skillDir, { schema_version: '1.3' }
            );
            assert.equal(result.valid, false);
            assert.equal(result.error_code, ErrorCode.DISCOVERY_INVALID);
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('should fail for missing signature file', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const skillDir = join(dir, 'skill');
            createSkillDir(skillDir, { 'SKILL.md': '# no signature here' });
            const result = verifySkillOffline(
                skillDir, { public_key_pem: 'dummy' }
            );
            assert.equal(result.valid, false);
            assert.equal(result.error_code, ErrorCode.SIGNATURE_INVALID);
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });
});

// ---------------------------------------------------------------------------
// Detect Tampered Files
// ---------------------------------------------------------------------------

describe('Detect Tampered Files', () => {
    it('should detect modified files', () => {
        const signed = { 'a.txt': 'sha256:aaa', 'b.txt': 'sha256:bbb' };
        const current = { 'a.txt': 'sha256:aaa', 'b.txt': 'sha256:ccc' };
        const diff = detectTamperedFiles(current, signed);
        assert.deepEqual(diff.modified, ['b.txt']);
        assert.deepEqual(diff.added, []);
        assert.deepEqual(diff.removed, []);
    });

    it('should detect added and removed files', () => {
        const signed = { 'a.txt': 'sha256:aaa', 'b.txt': 'sha256:bbb' };
        const current = { 'a.txt': 'sha256:aaa', 'new.txt': 'sha256:nnn' };
        const diff = detectTamperedFiles(current, signed);
        assert.deepEqual(diff.added, ['new.txt']);
        assert.deepEqual(diff.removed, ['b.txt']);
        assert.deepEqual(diff.modified, []);
    });

    it('should detect combined changes', () => {
        const signed = { 'keep.txt': 'sha256:k', 'mod.txt': 'sha256:old', 'gone.txt': 'sha256:g' };
        const current = { 'keep.txt': 'sha256:k', 'mod.txt': 'sha256:new', 'extra.txt': 'sha256:e' };
        const diff = detectTamperedFiles(current, signed);
        assert.deepEqual(diff.modified, ['mod.txt']);
        assert.deepEqual(diff.added, ['extra.txt']);
        assert.deepEqual(diff.removed, ['gone.txt']);
    });

    it('should return empty lists when no changes', () => {
        const m = { 'a.txt': 'sha256:aaa', 'b.txt': 'sha256:bbb' };
        const diff = detectTamperedFiles(m, m);
        assert.deepEqual(diff, { modified: [], added: [], removed: [] });
    });
});

// ---------------------------------------------------------------------------
// Load Signature
// ---------------------------------------------------------------------------

describe('Load Signature', () => {
    it('should load an existing signature file', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            mkdirSync(join(dir, 'skill'), { recursive: true });
            const sigData = { schemapin_version: '1.3', skill_name: 'test' };
            writeFileSync(
                join(dir, 'skill', SIGNATURE_FILENAME),
                JSON.stringify(sigData),
                'utf-8'
            );
            const loaded = loadSignature(join(dir, 'skill'));
            assert.deepEqual(loaded, sigData);
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('should throw for missing signature file', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            mkdirSync(join(dir, 'nosig'), { recursive: true });
            assert.throws(
                () => loadSignature(join(dir, 'nosig')),
                /not found/
            );
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });
});

// ---------------------------------------------------------------------------
// v1.4: Signature Expiration
// ---------------------------------------------------------------------------

const ONE_DAY_MS = 24 * 60 * 60 * 1000;

describe('Signature Expiration (v1.4)', () => {
    it('should write expires_at when expiresIn is set', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const { privateKey } = makeKeypair();
            const skillDir = join(dir, 'skill');
            createSkillDir(skillDir, { 'SKILL.md': '---\nname: ttl\n---\n# hi' });
            const sig = signSkillWithOptions(skillDir, privateKey, 'example.com', {
                expiresIn: 30 * ONE_DAY_MS
            });
            assert.equal(sig.schemapin_version, '1.4');
            assert.ok(typeof sig.expires_at === 'string', 'expires_at should be a string');
            assert.match(sig.expires_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);

            // Round-trip through disk to ensure the JSON contains expires_at.
            const onDisk = loadSignature(skillDir);
            assert.equal(onDisk.expires_at, sig.expires_at);
            assert.equal(onDisk.schemapin_version, '1.4');
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('should omit expires_at when expiresIn is not set', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const { privateKey } = makeKeypair();
            const skillDir = join(dir, 'skill');
            createSkillDir(skillDir, { 'SKILL.md': '---\nname: no-ttl\n---\n# hi' });
            const sig = signSkill(skillDir, privateKey, 'example.com');
            assert.equal(sig.schemapin_version, '1.4');
            assert.equal(sig.expires_at, undefined);

            const raw = readFileSync(join(skillDir, SIGNATURE_FILENAME), 'utf-8');
            assert.ok(!raw.includes('expires_at'), 'JSON should omit expires_at');
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('should verify with future TTL: valid, not expired, no warning', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const { privateKey, publicKey } = makeKeypair();
            const skillDir = join(dir, 'skill');
            createSkillDir(skillDir, { 'SKILL.md': '---\nname: future\n---\n# hi' });
            signSkillWithOptions(skillDir, privateKey, 'example.com', {
                expiresIn: 30 * ONE_DAY_MS
            });
            const result = verifySkillOffline(skillDir, makeDiscovery(publicKey));
            assert.equal(result.valid, true);
            assert.notEqual(result.expired, true);
            assert.ok(typeof result.expires_at === 'string');
            assert.ok(
                !result.warnings.includes('signature_expired'),
                'no expiration warning expected for future TTL'
            );
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('should verify with past TTL: valid (degraded), expired=true, warning', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const { privateKey, publicKey } = makeKeypair();
            const skillDir = join(dir, 'skill');
            createSkillDir(skillDir, { 'SKILL.md': '---\nname: past\n---\n# hi' });

            // Sign with a TTL that is already in the past (allowed at sign time).
            signSkillWithOptions(skillDir, privateKey, 'example.com', { expiresIn: -ONE_DAY_MS });

            const result = verifySkillOffline(skillDir, makeDiscovery(publicKey));
            assert.equal(result.valid, false, 'expired signatures fail closed by default');
            assert.equal(result.error_code, ErrorCode.SIGNATURE_EXPIRED);
            assert.equal(result.expired, true);

            const degraded = verifySkillOffline(skillDir, makeDiscovery(publicKey), null, null, null, null, null, true);
            assert.equal(degraded.valid, true, 'allowExpired restores degraded-not-failed');
            assert.equal(degraded.expired, true);
            assert.ok(degraded.warnings.includes('signature_expired'));
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('should fail closed when expires_at is unparseable (and warn with allowExpired)', () => {
        for (const bad of ['not-a-timestamp', '2020-01-01', '2020-01-01T00:00:00', '2020-01-01 00:00:00Z']) {
            const strict = applyExpirationCheck({ valid: true, warnings: [] }, bad);
            assert.equal(strict.valid, false, bad);
            assert.equal(strict.error_code, ErrorCode.SIGNATURE_EXPIRED);
            const lenient = applyExpirationCheck({ valid: true, warnings: [] }, bad, true);
            assert.equal(lenient.valid, true);
            assert.ok(lenient.warnings.includes('signature_expires_at_unparseable'));
        }
        // Inside the skew window is not expired.
        const justNow = new Date(Date.now() - 60 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
        assert.equal(applyExpirationCheck({ valid: true, warnings: [] }, justNow).valid, true);
    });

    it('covers expires_at with the signature: stripping it invalidates (SP-1)', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const { privateKey, publicKey } = makeKeypair();
            const skillDir = join(dir, 'skill');
            createSkillDir(skillDir, { 'SKILL.md': '---\nname: strip\n---\n# hi' });
            const sig = signSkillWithOptions(skillDir, privateKey, 'example.com', { expiresIn: -ONE_DAY_MS });
            const stripped = { ...sig };
            delete stripped.expires_at;
            writeFileSync(join(skillDir, SIGNATURE_FILENAME), JSON.stringify(stripped), 'utf-8');
            let r = verifySkillOffline(skillDir, makeDiscovery(publicKey));
            assert.equal(r.valid, false);
            assert.equal(r.error_code, ErrorCode.SIGNATURE_INVALID);
            stripped.schemapin_version = '1.3';
            writeFileSync(join(skillDir, SIGNATURE_FILENAME), JSON.stringify(stripped), 'utf-8');
            r = verifySkillOffline(skillDir, makeDiscovery(publicKey));
            assert.equal(r.valid, false);
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });
});

// ---------------------------------------------------------------------------
// v1.4: verifySkillOfflineWithDns integration
// ---------------------------------------------------------------------------

describe('verifySkillOfflineWithDns (v1.4)', () => {
    it('should pass when DNS TXT fingerprint matches discovery', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const { privateKey, publicKey } = makeKeypair();
            const skillDir = join(dir, 'skill');
            createSkillDir(skillDir, { 'SKILL.md': '---\nname: dnsok\n---\n# hi' });
            signSkill(skillDir, privateKey, 'example.com');

            const fp = KeyManager.calculateKeyFingerprint(publicKey).toLowerCase();
            const txt = { version: 'schemapin1', kid: null, fingerprint: fp };

            const result = verifySkillOfflineWithDns(
                skillDir, makeDiscovery(publicKey), null, null, null, 'dnsok', txt
            );
            assert.equal(result.valid, true);
            assert.equal(result.domain, 'example.com');
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('should fail with DOMAIN_MISMATCH when DNS TXT fingerprint does not match', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const { privateKey, publicKey } = makeKeypair();
            const skillDir = join(dir, 'skill');
            createSkillDir(skillDir, { 'SKILL.md': '---\nname: dnsbad\n---\n# hi' });
            signSkill(skillDir, privateKey, 'example.com');

            const txt = {
                version: 'schemapin1',
                kid: null,
                fingerprint: 'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            };
            const result = verifySkillOfflineWithDns(
                skillDir, makeDiscovery(publicKey), null, null, null, 'dnsbad', txt
            );
            assert.equal(result.valid, false);
            assert.equal(result.error_code, ErrorCode.DOMAIN_MISMATCH);
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('should be a no-op when dnsTxt is null', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const { privateKey, publicKey } = makeKeypair();
            const skillDir = join(dir, 'skill');
            createSkillDir(skillDir, { 'SKILL.md': '---\nname: nodns\n---\n# hi' });
            signSkill(skillDir, privateKey, 'example.com');

            const result = verifySkillOfflineWithDns(
                skillDir, makeDiscovery(publicKey), null, null, null, 'nodns', null
            );
            assert.equal(result.valid, true);
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });
});

// ---------------------------------------------------------------------------
// v1.4 alpha.2: schema_version + previous_hash lineage chain
// ---------------------------------------------------------------------------

describe('Schema version binding (v1.4 alpha.2)', () => {
    it('writes schema_version when set and bumps schemapin_version to 1.4', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const { privateKey } = makeKeypair();
            const skillDir = join(dir, 'skill');
            createSkillDir(skillDir, { 'SKILL.md': '---\nname: ver\n---\n' });
            const sig = signSkillWithOptions(skillDir, privateKey, 'example.com', {
                schemaVersion: '2.1.0'
            });
            assert.equal(sig.schema_version, '2.1.0');
            assert.equal(sig.schemapin_version, '1.4');
            const onDisk = loadSignature(skillDir);
            assert.equal(onDisk.schema_version, '2.1.0');
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('omits schema_version and previous_hash when not set', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const { privateKey } = makeKeypair();
            const skillDir = join(dir, 'skill');
            createSkillDir(skillDir, { 'SKILL.md': '---\nname: noversion\n---\n' });
            const sig = signSkill(skillDir, privateKey, 'example.com');
            assert.equal(sig.schema_version, undefined);
            assert.equal(sig.previous_hash, undefined);
            const raw = readFileSync(join(skillDir, SIGNATURE_FILENAME), 'utf-8');
            assert.ok(!raw.includes('schema_version'), 'JSON should omit schema_version');
            assert.ok(!raw.includes('previous_hash'), 'JSON should omit previous_hash');
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('writes previous_hash when set and bumps schemapin_version to 1.4', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const { privateKey } = makeKeypair();
            const skillDir = join(dir, 'skill');
            createSkillDir(skillDir, { 'SKILL.md': '---\nname: chained\n---\n' });
            const sig = signSkillWithOptions(skillDir, privateKey, 'example.com', {
                previousHash: 'sha256:abcdef'
            });
            assert.equal(sig.previous_hash, 'sha256:abcdef');
            assert.equal(sig.schemapin_version, '1.4');
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('verifyChain accepts a valid lineage', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const { privateKey } = makeKeypair();
            const s1 = createSkillDir(join(dir, 'v1'), { 'SKILL.md': '---\nname: v1\n---\n' });
            const v1 = signSkill(s1, privateKey, 'example.com');

            const s2 = createSkillDir(join(dir, 'v2'), { 'SKILL.md': '---\nname: v2\n---\n' });
            const v2 = signSkillWithOptions(s2, privateKey, 'example.com', {
                previousHash: v1.skill_hash
            });

            assert.doesNotThrow(() => verifyChain(v2, v1));
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('verifyChain throws ChainError when previous_hash is missing', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const { privateKey } = makeKeypair();
            const s1 = createSkillDir(join(dir, 'v1'), { 'SKILL.md': '---\nname: v1\n---\n' });
            const s2 = createSkillDir(join(dir, 'v2'), { 'SKILL.md': '---\nname: v2\n---\n' });
            const v1 = signSkill(s1, privateKey, 'example.com');
            const v2 = signSkill(s2, privateKey, 'example.com');
            assert.throws(
                () => verifyChain(v2, v1),
                (err) => err instanceof ChainError && err.kind === 'no_previous_hash'
            );
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('verifyChain throws ChainError on hash mismatch', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const { privateKey } = makeKeypair();
            const s1 = createSkillDir(join(dir, 'v1'), { 'SKILL.md': '---\nname: v1\n---\n' });
            const s2 = createSkillDir(join(dir, 'v2'), { 'SKILL.md': '---\nname: v2\n---\n' });
            const v1 = signSkill(s1, privateKey, 'example.com');
            const v2 = signSkillWithOptions(s2, privateKey, 'example.com', {
                previousHash: 'sha256:not-the-real-prior-hash'
            });
            assert.throws(
                () => verifyChain(v2, v1),
                (err) => err instanceof ChainError
                    && err.kind === 'mismatch'
                    && err.message.includes(v1.skill_hash)
            );
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('verifySkillOffline surfaces lineage metadata', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const { privateKey, publicKey } = makeKeypair();
            const skillDir = join(dir, 'skill');
            createSkillDir(skillDir, { 'SKILL.md': '---\nname: surfaced\n---\n' });
            signSkillWithOptions(skillDir, privateKey, 'example.com', {
                schemaVersion: '3.2.1',
                previousHash: 'sha256:deadbeef'
            });
            const result = verifySkillOffline(
                skillDir, makeDiscovery(publicKey), null, null, new KeyPinStore(), 'surfaced'
            );
            assert.equal(result.valid, true);
            assert.equal(result.schema_version, '3.2.1');
            assert.equal(result.previous_hash, 'sha256:deadbeef');
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('combined v1.4 fields all round-trip', () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const { privateKey } = makeKeypair();
            const skillDir = join(dir, 'skill');
            createSkillDir(skillDir, { 'SKILL.md': '---\nname: combo\n---\n' });
            const sig = signSkillWithOptions(skillDir, privateKey, 'example.com', {
                expiresIn: 180 * 24 * 60 * 60 * 1000, // 180 days in ms
                schemaVersion: '1.0.0',
                previousHash: 'sha256:cafebabe'
            });
            assert.equal(sig.schemapin_version, '1.4');
            assert.ok(typeof sig.expires_at === 'string');
            assert.equal(sig.schema_version, '1.0.0');
            assert.equal(sig.previous_hash, 'sha256:cafebabe');

            const onDisk = loadSignature(skillDir);
            assert.equal(onDisk.expires_at, sig.expires_at);
            assert.equal(onDisk.schema_version, '1.0.0');
            assert.equal(onDisk.previous_hash, 'sha256:cafebabe');
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });
});


// ---------------------------------------------------------------------------
// Signed signature document, domain binding, hashing v2 (SP-1, 8, 12, 13, 14)
// ---------------------------------------------------------------------------

function signLegacyV13(skillDir, privateKey, domain) {
    const { rootHash, manifest } = canonicalizeSkillV1(skillDir);
    const publicKeyPem = nodeCrypto.createPublicKey(privateKey).export({ type: 'spki', format: 'pem' });
    const sig = {
        schemapin_version: '1.3',
        skill_name: 'legacy',
        skill_hash: `sha256:${rootHash.toString('hex')}`,
        signature: SignatureManager.signHash(rootHash, privateKey),
        signed_at: '2026-01-01T00:00:00Z',
        domain,
        signer_kid: KM.calculateKeyFingerprint(publicKeyPem),
        file_manifest: manifest
    };
    writeFileSync(join(skillDir, SIGNATURE_FILENAME), JSON.stringify(sig), 'utf-8');
    return sig;
}

function withTmp(fn) {
    const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
    try {
        return fn(dir);
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }
}

describe('signed signature document (SP-1)', () => {
    for (const [field, value] of [
        ['schema_version', '9.9.9'],
        ['previous_hash', 'sha256:' + 'ab'.repeat(32)],
        ['skill_name', 'payments-tool'],
        ['domain', 'good.example.com'],
        ['signer_kid', 'sha256:' + '00'.repeat(32)],
        ['signed_at', '2030-01-01T00:00:00Z'],
        ['canonicalization', 'schemapin-v1']
    ]) {
        it(`tampering ${field} invalidates the signature`, () => withTmp((dir) => {
            const { privateKey, publicKey } = makeKeypair();
            const skillDir = join(dir, 'skill');
            createSkillDir(skillDir, { 'SKILL.md': '---\nname: s\n---\n# hi' });
            signSkillWithOptions(skillDir, privateKey, 'example.com', { schemaVersion: '1.0.0' });
            const sig = loadSignature(skillDir);
            sig[field] = value;
            writeFileSync(join(skillDir, SIGNATURE_FILENAME), JSON.stringify(sig), 'utf-8');
            const r = verifySkillOffline(skillDir, makeDiscovery(publicKey));
            assert.equal(r.valid, false);
        }));
    }

    it('verifies skill_hash against the directory (SP-14)', () => withTmp((dir) => {
        const { privateKey, publicKey } = makeKeypair();
        const skillDir = join(dir, 'skill');
        createSkillDir(skillDir, { 'SKILL.md': '# hi' });
        const sig = signSkill(skillDir, privateKey, 'example.com');
        assert.equal(sig.skill_hash, `sha256:${canonicalizeSkill(skillDir).rootHash.toString('hex')}`);
        const other = join(dir, 'other');
        createSkillDir(other, { 'SKILL.md': '# other' });
        signSkill(other, privateKey, 'example.com');
        writeFileSync(join(skillDir, SIGNATURE_FILENAME), JSON.stringify(loadSignature(other)), 'utf-8');
        const r = verifySkillOffline(skillDir, makeDiscovery(publicKey));
        assert.equal(r.valid, false);
        assert.match(r.error_message, /skill_hash/);
    }));

    it('still verifies legacy 1.3 documents with a warning', () => withTmp((dir) => {
        const { privateKey, publicKey } = makeKeypair();
        const skillDir = join(dir, 'skill');
        createSkillDir(skillDir, { 'SKILL.md': '# hi', 'sub/x.txt': 'x' });
        signLegacyV13(skillDir, privateKey, 'example.com');
        const r = verifySkillOffline(skillDir, makeDiscovery(publicKey), null, null, null, null, 'example.com');
        assert.equal(r.valid, true);
        assert.ok(r.warnings.includes('legacy_signature_format'));
        const sig = loadSignature(skillDir);
        sig.schemapin_version = '1.4';
        writeFileSync(join(skillDir, SIGNATURE_FILENAME), JSON.stringify(sig), 'utf-8');
        assert.equal(verifySkillOffline(skillDir, makeDiscovery(publicKey)).valid, false);
    }));

    it('verifyChain rejects legacy documents', () => {
        assert.throws(
            () => verifyChain({ schemapin_version: '1.4', previous_hash: 'sha256:aa' }, { schemapin_version: '1.3', skill_hash: 'sha256:aa' }),
            (e) => e instanceof ChainError && e.kind === 'legacy'
        );
    });
});

describe('domain binding (SP-8)', () => {
    it('offline: mismatch fails and nothing is pinned', () => withTmp((dir) => {
        const { privateKey, publicKey } = makeKeypair();
        const skillDir = join(dir, 'skill');
        createSkillDir(skillDir, { 'SKILL.md': '# hi' });
        signSkill(skillDir, privateKey, 'evil.example.com');
        const store = new KeyPinStore();
        const r = verifySkillOffline(skillDir, makeDiscovery(publicKey), null, null, store, 'calc', 'good.example.com');
        assert.equal(r.valid, false);
        assert.equal(r.error_code, ErrorCode.DOMAIN_MISMATCH);
        assert.equal(store.getPinned('calc', 'good.example.com'), null);
        assert.equal(store.getPinned('calc', 'evil.example.com'), null);
    }));

    it('offline: bound domain is reported, unbound is warned', () => withTmp((dir) => {
        const { privateKey, publicKey } = makeKeypair();
        const skillDir = join(dir, 'skill');
        createSkillDir(skillDir, { 'SKILL.md': '# hi' });
        signSkill(skillDir, privateKey, 'Example.COM');
        const r = verifySkillOffline(skillDir, makeDiscovery(publicKey), null, null, null, null, 'example.com');
        assert.equal(r.valid, true);
        assert.equal(r.domain, 'example.com');
        assert.ok(!r.warnings.includes('domain_unbound'));
        const r2 = verifySkillOffline(skillDir, makeDiscovery(publicKey));
        assert.ok(r2.warnings.includes('domain_unbound'));
    }));

    it('resolver path binds the domain before any network access', async () => {
        const dir = mkdtempSync(join(tmpdir(), 'skill-test-'));
        try {
            const { privateKey } = makeKeypair();
            const skillDir = join(dir, 'skill');
            createSkillDir(skillDir, { 'SKILL.md': '# hi' });
            signSkill(skillDir, privateKey, 'good.example.com');
            class Exploding extends SchemaResolver {
                async resolveDiscovery() { throw new Error('network must not be touched'); }
                async resolveRevocation() { throw new Error('unreachable'); }
            }
            const r = await verifySkillWithResolver(skillDir, 'evil.example.com', new Exploding());
            assert.equal(r.valid, false);
            assert.equal(r.error_code, ErrorCode.DOMAIN_MISMATCH);
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('rejects invalid domains', () => withTmp((dir) => {
        const { privateKey, publicKey } = makeKeypair();
        const skillDir = join(dir, 'skill');
        createSkillDir(skillDir, { 'SKILL.md': '# hi' });
        signSkill(skillDir, privateKey, 'example.com');
        for (const bad of ['../skills/evil/key', 'localhost', 'http://example.com', '10.0.0.1']) {
            const r = verifySkillOffline(skillDir, makeDiscovery(publicKey), null, null, null, null, bad);
            assert.equal(r.valid, false, bad);
            assert.equal(r.error_code, ErrorCode.DOMAIN_INVALID, bad);
        }
    }));
});

describe('pin after verify', () => {
    it('a failed signature never leaves a pin behind', () => withTmp((dir) => {
        const { privateKey, publicKey } = makeKeypair();
        const other = makeKeypair();
        const skillDir = join(dir, 'skill');
        createSkillDir(skillDir, { 'SKILL.md': '# hi' });
        signSkill(skillDir, privateKey, 'example.com');
        const store = new KeyPinStore();
        let r = verifySkillOffline(skillDir, makeDiscovery(other.publicKey), null, null, store, 't', 'example.com');
        assert.equal(r.valid, false);
        assert.equal(store.getPinned('t', 'example.com'), null);
        r = verifySkillOffline(skillDir, makeDiscovery(publicKey), null, null, store, 't', 'example.com');
        assert.equal(r.valid, true);
        assert.equal(r.key_pinning.status, 'first_use');
        assert.notEqual(store.getPinned('t', 'example.com'), null);
    }));

    it('an expired signature never leaves a pin behind', () => withTmp((dir) => {
        const { privateKey, publicKey } = makeKeypair();
        const skillDir = join(dir, 'skill');
        createSkillDir(skillDir, { 'SKILL.md': '# hi' });
        signSkillWithOptions(skillDir, privateKey, 'example.com', { expiresIn: -ONE_DAY_MS });
        const store = new KeyPinStore();
        const r = verifySkillOffline(skillDir, makeDiscovery(publicKey), null, null, store, 't', 'example.com');
        assert.equal(r.valid, false);
        assert.equal(store.getPinned('t', 'example.com'), null);
    }));
});

describe('skill hashing v2 (SP-12 / SP-13)', () => {
    it('rejects symlinked files and directories', () => withTmp((dir) => {
        const skillDir = join(dir, 'skill');
        createSkillDir(skillDir, { 'SKILL.md': '# hi' });
        writeFileSync(join(dir, 'outside.txt'), 'unsigned');
        symlinkSync(join(dir, 'outside.txt'), join(skillDir, 'link.txt'));
        assert.throws(() => canonicalizeSkill(skillDir), SkillCanonicalizationError);
        rmSync(join(skillDir, 'link.txt'));
        mkdirSync(join(dir, 'other'));
        symlinkSync(join(dir, 'other'), join(skillDir, 'examples'), 'dir');
        assert.throws(() => canonicalizeSkill(skillDir), SkillCanonicalizationError);
    }));

    it('a symlink added after signing fails verification', () => withTmp((dir) => {
        const { privateKey, publicKey } = makeKeypair();
        const skillDir = join(dir, 'skill');
        createSkillDir(skillDir, { 'SKILL.md': '# hi' });
        signSkill(skillDir, privateKey, 'example.com');
        writeFileSync(join(dir, 'outside.txt'), 'unsigned');
        symlinkSync(join(dir, 'outside.txt'), join(skillDir, 'helper.sh'));
        const r = verifySkillOffline(skillDir, makeDiscovery(publicKey));
        assert.equal(r.valid, false);
        assert.equal(r.error_code, ErrorCode.SCHEMA_CANONICALIZATION_FAILED);
    }));

    it('path/content boundary is not malleable', () => withTmp((dir) => {
        const a = join(dir, 'a');
        const b = join(dir, 'b');
        createSkillDir(a, { 'run.sh.disabled': '\necho hi' });
        createSkillDir(b, { 'run.sh': '.disabled\necho hi' });
        assert.notDeepEqual(canonicalizeSkill(a).rootHash, canonicalizeSkill(b).rootHash);
        // The legacy algorithm collides on exactly this re-split.
        assert.deepEqual(canonicalizeSkillV1(a).rootHash, canonicalizeSkillV1(b).rootHash);
    }));

    it('a nested .schemapin.sig is content, the top-level one is not', () => withTmp((dir) => {
        const skillDir = join(dir, 'skill');
        createSkillDir(skillDir, { 'SKILL.md': '# hi', 'nested/.schemapin.sig': '{}' });
        const { manifest } = canonicalizeSkill(skillDir);
        assert.ok('nested/.schemapin.sig' in manifest);
        assert.ok(!('.schemapin.sig' in manifest));
    }));
});
