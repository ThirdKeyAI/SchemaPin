/**
 * Property-based tests for the parsers that face untrusted input.
 *
 * Uses a small seeded generator (no extra dependency) to produce random JSON
 * values and random strings: canonicalization must be idempotent and the
 * parsers must fail only with their documented error types.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { SchemaPinCore, CanonicalizationError, MAX_SAFE_INTEGER } from '../src/core.js';
import { parseTxtRecord } from '../src/dns.js';
import { InvalidDomainError, validateDomain } from '../src/domain.js';
import { signingInput } from '../src/skill.js';

function rng(seed) {
    let s = seed >>> 0;
    return () => {
        s = (s + 0x6d2b79f5) >>> 0;
        let t = s;
        t = Math.imul(t ^ (t >>> 15), t | 1);
        t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}

const ALPHABET = 'ab\u00e9\u65e5\u{1F600}"\\/<>&\n\t\u0000\u2028\u2029 .-_@:{}[],0123456789';

function randomString(r, max = 8) {
    const n = Math.floor(r() * max);
    let out = '';
    for (let i = 0; i < n; i++) {
        const chars = Array.from(ALPHABET);
        out += chars[Math.floor(r() * chars.length)];
    }
    return out;
}

function randomValue(r, depth = 0) {
    const k = r();
    if (depth > 3 || k < 0.15) return null;
    if (k < 0.3) return r() < 0.5;
    if (k < 0.5) return Math.floor((r() * 2 - 1) * MAX_SAFE_INTEGER);
    if (k < 0.6) return (r() * 2 - 1) * 1e15 / (1 + r() * 1e6);
    if (k < 0.75) return randomString(r);
    if (k < 0.88) return Array.from({ length: Math.floor(r() * 4) }, () => randomValue(r, depth + 1));
    const obj = {};
    for (let i = 0; i < Math.floor(r() * 4); i++) obj[randomString(r)] = randomValue(r, depth + 1);
    return obj;
}

describe('property: canonicalization', () => {
    test('is idempotent and agrees with JSON.parse on its own output', () => {
        const r = rng(42);
        for (let i = 0; i < 500; i++) {
            const value = randomValue(r);
            const canonical = SchemaPinCore.canonicalizeSchema(value);
            const reparsed = SchemaPinCore.parseSchemaJson(canonical);
            assert.equal(SchemaPinCore.canonicalizeSchema(reparsed), canonical);
            assert.deepEqual(JSON.parse(canonical), reparsed);
        }
    });

    test('strict parser only throws CanonicalizationError', () => {
        const r = rng(7);
        for (let i = 0; i < 1000; i++) {
            const text = randomString(r, 24);
            try {
                SchemaPinCore.canonicalizeSchema(SchemaPinCore.parseSchemaJson(text));
            } catch (e) {
                assert.ok(e instanceof CanonicalizationError, `${e.name}: ${e.message}`);
            }
        }
    });
});

describe('property: untrusted-input parsers', () => {
    test('TXT parser and domain validator only throw their documented errors', () => {
        const r = rng(99);
        for (let i = 0; i < 1000; i++) {
            const text = randomString(r, 32);
            try {
                assert.ok(parseTxtRecord(text).fingerprint.startsWith('sha256:'));
            } catch (e) {
                assert.ok(e instanceof Error && !(e instanceof TypeError) && !(e instanceof RangeError), e.name);
            }
            try {
                const normalized = validateDomain(text);
                assert.equal(validateDomain(normalized), normalized);
            } catch (e) {
                assert.ok(e instanceof InvalidDomainError, e.name);
            }
        }
    });

    test('signing input only throws Error on arbitrary documents', () => {
        const r = rng(5);
        for (let i = 0; i < 500; i++) {
            const doc = randomValue(r, 2);
            if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) continue;
            try {
                signingInput(doc);
            } catch (e) {
                assert.ok(e instanceof Error && !(e instanceof TypeError), e.name);
            }
        }
    });
});
