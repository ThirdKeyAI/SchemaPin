/**
 * Tests for the verifier-side LineageStore (design issue 3).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { LineageError, LineageStore, versionIncreases } from '../src/lineage.js';

const doc = (skillHash, previous = null, version = null, schemapin = '1.4') => ({
    schemapin_version: schemapin,
    skill_hash: skillHash,
    ...(previous !== null ? { previous_hash: previous } : {}),
    ...(version !== null ? { schema_version: version } : {})
});

describe('LineageStore', () => {
    test('first use, advance, unchanged', () => {
        const store = new LineageStore();
        assert.equal(store.checkAndAdvance('calc', 'example.com', doc('sha256:a', null, '1.0.0')), 'first_use');
        assert.equal(store.checkAndAdvance('calc', 'example.com', doc('sha256:a', null, '1.0.0')), 'unchanged');
        assert.equal(store.checkAndAdvance('calc', 'example.com', doc('sha256:b', 'sha256:a', '1.1.0')), 'advanced');
        assert.equal(store.get('calc', 'example.com').skill_hash, 'sha256:b');
    });

    test('forks and rollbacks are rejected', () => {
        const store = new LineageStore();
        store.checkAndAdvance('calc', 'example.com', doc('sha256:v4'));
        store.checkAndAdvance('calc', 'example.com', doc('sha256:v5', 'sha256:v4'));
        assert.throws(() => store.checkAndAdvance('calc', 'example.com', doc('sha256:v5x', 'sha256:v4')), /fork or rollback/);
        assert.throws(() => store.checkAndAdvance('calc', 'example.com', doc('sha256:v6')), /no previous_hash/);
        assert.equal(store.checkAndAdvance('calc', 'example.com', doc('sha256:v6'), false), 'advanced');
    });

    test('schema_version must increase', () => {
        const store = new LineageStore();
        store.checkAndAdvance('calc', 'example.com', doc('sha256:a', null, '1.9.0'));
        assert.throws(() => store.checkAndAdvance('calc', 'example.com', doc('sha256:b', 'sha256:a', '1.9.0')), LineageError);
        assert.throws(() => store.checkAndAdvance('calc', 'example.com', doc('sha256:b', 'sha256:a', '1.2.0')), LineageError);
        assert.equal(store.checkAndAdvance('calc', 'example.com', doc('sha256:b', 'sha256:a', '1.10.0')), 'advanced');
        assert.equal(versionIncreases('1.9.0', '1.10.0'), true);
        assert.equal(versionIncreases('2.0.0', '2.0.0'), false);
        assert.equal(versionIncreases('abc', 'abd'), true);
    });

    test('legacy documents refused; tools isolated; JSON round trip', () => {
        const store = new LineageStore();
        assert.throws(() => store.checkAndAdvance('calc', 'example.com', doc('sha256:a', null, null, '1.3')), /legacy/);
        store.seed('calc', 'example.com', 'sha256:a', '1.0.0');
        assert.equal(store.checkAndAdvance('calc', 'other.com', doc('sha256:z')), 'first_use');
        const restored = LineageStore.fromJSON(store.toJSON());
        assert.equal(restored.get('calc', 'example.com').schema_version, '1.0.0');
        assert.throws(() => LineageStore.fromJSON('[]'));
    });
});
