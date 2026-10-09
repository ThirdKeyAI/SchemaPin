/**
 * Regression tests for the legacy KeyPinning store (SP-15).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, statSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { KeyPinning, PinningMode, PinStoreCorruptError } from '../src/pinning.js';
import { UserDecision } from '../src/interactive.js';

const PEM_A = '-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----';
const PEM_B = '-----BEGIN PUBLIC KEY-----\nBBBB\n-----END PUBLIC KEY-----';
const NOT_REVOKED = { revocationChecker: async () => true };

function withTmp(fn) {
    const dir = mkdtempSync(join(tmpdir(), 'pin-store-'));
    try {
        return fn(dir);
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }
}

describe('legacy KeyPinning store (SP-15)', () => {
    test('pins are bound to the domain', () => withTmp((dir) => {
        const store = new KeyPinning(join(dir, 'pins.json'), PinningMode.AUTOMATIC, null, NOT_REVOKED);
        assert.equal(store.pinKey('calculator', PEM_A, 'evil.com'), true);
        assert.equal(store.getPinnedKey('calculator', 'good.com'), null);
        assert.equal(store.isKeyPinned('calculator', 'good.com'), false);
        assert.equal(store.getPinnedKey('calculator', 'evil.com'), PEM_A);
        assert.equal(store.pinKey('calculator', PEM_B, 'good.com'), true);
        assert.equal(store.getPinnedKey('calculator', 'good.com'), PEM_B);
        // Deprecated domain-less lookup refuses to guess between domains.
        assert.equal(store.getPinnedKey('calculator'), null);
        assert.equal(store.removePinnedKey('calculator', 'evil.com'), true);
        assert.equal(store.getPinnedKey('calculator'), PEM_B);
        const listed = store.listPinnedKeys();
        assert.deepEqual(listed.map((k) => [k.tool_id, k.domain]), [['calculator', 'good.com']]);
    }));

    test('a corrupt store is a hard error, not a silent reset', () => withTmp((dir) => {
        const path = join(dir, 'pins.json');
        writeFileSync(path, '{"pinned_keys": {"calc@example.com": {"public_key_pem": "x", "domain": "example.com"}}', 'utf8');
        assert.throws(() => new KeyPinning(path, PinningMode.AUTOMATIC, null, NOT_REVOKED), PinStoreCorruptError);
        writeFileSync(path, '[]', 'utf8');
        assert.throws(() => new KeyPinning(path, PinningMode.AUTOMATIC, null, NOT_REVOKED), PinStoreCorruptError);
    }));

    test('legacy layouts are migrated to toolId@domain keys', () => withTmp((dir) => {
        const path = join(dir, 'pins.json');
        writeFileSync(path, JSON.stringify({
            pinned_keys: { calc: { public_key_pem: PEM_A, domain: 'example.com', developer_name: null, pinned_at: '2026-01-01T00:00:00.000Z', last_verified: null } },
            domain_policies: {}
        }), 'utf8');
        const store = new KeyPinning(path, PinningMode.AUTOMATIC, null, NOT_REVOKED);
        assert.equal(store.getPinnedKey('calc', 'example.com'), PEM_A);
        const onDisk = JSON.parse(readFileSync(path, 'utf8'));
        assert.ok('calc@example.com' in onDisk.pinned_keys);
        assert.ok(!('calc' in onDisk.pinned_keys));
    }));

    test('writes are atomic and owner-only', () => withTmp((dir) => {
        const path = join(dir, 'pins.json');
        const store = new KeyPinning(path, PinningMode.AUTOMATIC, null, NOT_REVOKED);
        store.pinKey('calc', PEM_A, 'example.com');
        assert.deepEqual(readdirSync(dir), ['pins.json'], 'no temp files left behind');
        if (process.platform !== 'win32') {
            assert.equal((statSync(path).mode & 0o777).toString(8), '600');
        }
    }));

    test('interactive flows check revocation before pinning', async () => {
        const dir = mkdtempSync(join(tmpdir(), 'pin-store-'));
        try {
            const revoked = { revocationChecker: async () => false };
            const store = new KeyPinning(join(dir, 'pins.json'), PinningMode.AUTOMATIC, null, revoked);
            assert.equal(await store.interactivePinKey('calc', PEM_A, 'example.com', 'Dev'), false);
            assert.equal(store.isKeyPinned('calc', 'example.com'), false);
            // With an interactive handler the user may temporarily accept, but
            // the key is still never pinned.
            const handler = { promptUser: async () => UserDecision.TEMPORARY_ACCEPT };
            const interactive = new KeyPinning(join(dir, 'pins2.json'), PinningMode.INTERACTIVE, handler, revoked);
            assert.equal(await interactive.interactivePinKey('calc', PEM_A, 'example.com', 'Dev'), true);
            assert.equal(interactive.isKeyPinned('calc', 'example.com'), false);
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });
});
