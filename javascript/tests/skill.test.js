/**
 * Tests for skill folder signing and verification.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { KeyManager } from '../src/crypto.js';
import { buildRevocationDocument, addRevokedKey, RevocationReason } from '../src/revocation.js';
import { ErrorCode, KeyPinStore } from '../src/verification.js';
import {
    SIGNATURE_FILENAME, canonicalizeSkill, parseSkillName, loadSignature,
    signSkill, verifySkillOffline, detectTamperedFiles
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
            assert.equal(sig.schemapin_version, '1.3');
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
