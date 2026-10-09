/**
 * Core SchemaPin functionality for schema canonicalization and hashing.
 *
 * Implements the `schemapin-v1` canonical JSON serialization specified in
 * TECHNICAL_SPECIFICATION.md section 4. The rules are strict so that every
 * SDK produces byte-identical output:
 *
 * - Object keys are sorted by Unicode code point (NOT by UTF-16 code unit,
 *   which is what `Array.prototype.sort` would do for astral characters).
 * - Duplicate object keys, `NaN`/`Infinity`, lone surrogates and invalid
 *   UTF-8 are rejected -- they have no canonical form.
 * - Strings are escaped minimally: `"` and `\` are backslash-escaped,
 *   U+0008/U+000C/U+000A/U+000D/U+0009 use `\b \f \n \r \t`, the remaining
 *   C0 controls use lowercase `\u00xx`, and everything else (including
 *   `<`, `>`, `&`, U+007F, U+2028 and U+2029) is emitted literally.
 * - Numbers are IEEE-754 binary64. Any value whose magnitude exceeds
 *   2**53 - 1 is rejected. Integral values are emitted as plain decimal
 *   integers (`-0` -> `0`); non-integral values use ECMAScript
 *   `Number::toString` (RFC 8785 section 3.2.2.3).
 * - `__proto__` is an ordinary key and is preserved. The serializer never
 *   materializes intermediate objects, so no prototype setter can fire.
 */

import { createHash } from 'crypto';

/** Largest integer magnitude accepted by the canonicalizer (2**53 - 1). */
export const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;

const MAX_DEPTH = 512;

/**
 * Thrown when a value has no `schemapin-v1` canonical form.
 */
export class CanonicalizationError extends Error {
    constructor(message) {
        super(message);
        this.name = 'CanonicalizationError';
    }
}

/**
 * Compare two strings by Unicode code point.
 *
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
export function compareCodePoints(a, b) {
    let i = 0;
    let j = 0;
    while (i < a.length && j < b.length) {
        const ca = a.codePointAt(i);
        const cb = b.codePointAt(j);
        if (ca !== cb) {
            return ca < cb ? -1 : 1;
        }
        i += ca > 0xffff ? 2 : 1;
        j += cb > 0xffff ? 2 : 1;
    }
    if (i >= a.length && j >= b.length) {
        return 0;
    }
    return i >= a.length ? -1 : 1;
}

const SHORT_ESCAPES = {
    '"': '\\"',
    '\\': '\\\\',
    '\b': '\\b',
    '\f': '\\f',
    '\n': '\\n',
    '\r': '\\r',
    '\t': '\\t'
};

function canonicalString(value) {
    let out = '"';
    for (let i = 0; i < value.length; i++) {
        const code = value.charCodeAt(i);
        if (code >= 0xd800 && code <= 0xdbff) {
            const next = i + 1 < value.length ? value.charCodeAt(i + 1) : 0;
            if (next < 0xdc00 || next > 0xdfff) {
                throw new CanonicalizationError(
                    `lone surrogate U+${code.toString(16).toUpperCase()} has no canonical form`
                );
            }
            out += value[i] + value[i + 1];
            i++;
            continue;
        }
        if (code >= 0xdc00 && code <= 0xdfff) {
            throw new CanonicalizationError(
                `lone surrogate U+${code.toString(16).toUpperCase()} has no canonical form`
            );
        }
        const ch = value[i];
        const esc = SHORT_ESCAPES[ch];
        if (esc !== undefined) {
            out += esc;
        } else if (code < 0x20) {
            out += '\\u' + code.toString(16).padStart(4, '0');
        } else {
            out += ch;
        }
    }
    return out + '"';
}

function canonicalNumber(value) {
    if (typeof value === 'bigint') {
        if (value > BigInt(MAX_SAFE_INTEGER) || value < -BigInt(MAX_SAFE_INTEGER)) {
            throw new CanonicalizationError(`integer ${value} exceeds the 2**53-1 safe range`);
        }
        return value.toString();
    }
    if (!Number.isFinite(value)) {
        throw new CanonicalizationError('NaN and Infinity are not valid JSON');
    }
    if (Math.abs(value) > MAX_SAFE_INTEGER) {
        throw new CanonicalizationError(`number ${value} exceeds the 2**53-1 safe range`);
    }
    if (Object.is(value, -0)) {
        return '0';
    }
    // Integral values within the safe range print as plain decimals; the
    // non-integral case is exactly ECMAScript Number::toString.
    return String(value);
}

function canonicalValue(value, depth) {
    if (depth > MAX_DEPTH) {
        throw new CanonicalizationError('nesting depth exceeds limit');
    }
    if (value === null) {
        return 'null';
    }
    switch (typeof value) {
    case 'boolean':
        return value ? 'true' : 'false';
    case 'string':
        return canonicalString(value);
    case 'number':
    case 'bigint':
        return canonicalNumber(value);
    case 'object':
        break;
    default:
        throw new CanonicalizationError(`unsupported value type ${typeof value}`);
    }
    if (typeof value.toJSON === 'function') {
        return canonicalValue(value.toJSON(), depth + 1);
    }
    if (Array.isArray(value)) {
        const parts = [];
        for (const item of value) {
            if (item === undefined) {
                throw new CanonicalizationError('undefined array element has no canonical form');
            }
            parts.push(canonicalValue(item, depth + 1));
        }
        return '[' + parts.join(',') + ']';
    }
    const keys = Object.keys(value).sort(compareCodePoints);
    const parts = [];
    for (const key of keys) {
        const v = value[key];
        if (v === undefined || typeof v === 'function' || typeof v === 'symbol') {
            continue;
        }
        parts.push(canonicalString(key) + ':' + canonicalValue(v, depth + 1));
    }
    return '{' + parts.join(',') + '}';
}

// ─────────────────────────────────────────────────────────────────────────
// Strict JSON parser
// ─────────────────────────────────────────────────────────────────────────

class StrictParser {
    constructor(text) {
        this.text = text;
        this.pos = 0;
    }

    fail(message) {
        throw new CanonicalizationError(`invalid JSON at offset ${this.pos}: ${message}`);
    }

    skipWs() {
        const t = this.text;
        while (this.pos < t.length) {
            const c = t.charCodeAt(this.pos);
            if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) {
                this.pos++;
            } else {
                break;
            }
        }
    }

    parseDocument() {
        this.skipWs();
        const value = this.parseValue(0);
        this.skipWs();
        if (this.pos !== this.text.length) {
            this.fail('trailing characters');
        }
        return value;
    }

    parseValue(depth) {
        if (depth > MAX_DEPTH) {
            this.fail('nesting depth exceeds limit');
        }
        const t = this.text;
        if (this.pos >= t.length) {
            this.fail('unexpected end of input');
        }
        const ch = t[this.pos];
        switch (ch) {
        case '{':
            return this.parseObject(depth);
        case '[':
            return this.parseArray(depth);
        case '"':
            return this.parseString();
        case 't':
            return this.parseLiteral('true', true);
        case 'f':
            return this.parseLiteral('false', false);
        case 'n':
            return this.parseLiteral('null', null);
        default:
            if (ch === '-' || (ch >= '0' && ch <= '9')) {
                return this.parseNumber();
            }
            return this.fail(`unexpected character '${ch}'`);
        }
    }

    parseLiteral(word, value) {
        if (this.text.startsWith(word, this.pos)) {
            this.pos += word.length;
            return value;
        }
        return this.fail(`expected ${word}`);
    }

    parseNumber() {
        const m = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(this.text.slice(this.pos));
        if (!m) {
            this.fail('malformed number');
        }
        this.pos += m[0].length;
        const value = Number(m[0]);
        if (!Number.isFinite(value) || Math.abs(value) > MAX_SAFE_INTEGER) {
            throw new CanonicalizationError(`number ${m[0]} exceeds the 2**53-1 safe range`);
        }
        return value;
    }

    parseString() {
        const t = this.text;
        this.pos++; // opening quote
        let out = '';
        for (;;) {
            if (this.pos >= t.length) {
                this.fail('unterminated string');
            }
            const code = t.charCodeAt(this.pos);
            if (code === 0x22) {
                this.pos++;
                return out;
            }
            if (code < 0x20) {
                this.fail('unescaped control character in string');
            }
            if (code === 0x5c) {
                out += this.parseEscape();
                continue;
            }
            if (code >= 0xd800 && code <= 0xdbff) {
                const next = this.pos + 1 < t.length ? t.charCodeAt(this.pos + 1) : 0;
                if (next < 0xdc00 || next > 0xdfff) {
                    this.fail('lone surrogate in string');
                }
                out += t[this.pos] + t[this.pos + 1];
                this.pos += 2;
                continue;
            }
            if (code >= 0xdc00 && code <= 0xdfff) {
                this.fail('lone surrogate in string');
            }
            out += t[this.pos];
            this.pos++;
        }
    }

    parseEscape() {
        const t = this.text;
        this.pos++; // backslash
        if (this.pos >= t.length) {
            this.fail('unterminated escape');
        }
        const ch = t[this.pos++];
        switch (ch) {
        case '"': return '"';
        case '\\': return '\\';
        case '/': return '/';
        case 'b': return '\b';
        case 'f': return '\f';
        case 'n': return '\n';
        case 'r': return '\r';
        case 't': return '\t';
        case 'u': {
            const hi = this.parseHex4();
            if (hi >= 0xd800 && hi <= 0xdbff) {
                if (t[this.pos] !== '\\' || t[this.pos + 1] !== 'u') {
                    this.fail('lone high surrogate escape');
                }
                this.pos += 2;
                const lo = this.parseHex4();
                if (lo < 0xdc00 || lo > 0xdfff) {
                    this.fail('lone high surrogate escape');
                }
                return String.fromCharCode(hi, lo);
            }
            if (hi >= 0xdc00 && hi <= 0xdfff) {
                this.fail('lone low surrogate escape');
            }
            return String.fromCharCode(hi);
        }
        default:
            return this.fail(`invalid escape \\${ch}`);
        }
    }

    parseHex4() {
        const hex = this.text.slice(this.pos, this.pos + 4);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
            this.fail('invalid \\u escape');
        }
        this.pos += 4;
        return parseInt(hex, 16);
    }

    parseArray(depth) {
        this.pos++; // [
        const out = [];
        this.skipWs();
        if (this.text[this.pos] === ']') {
            this.pos++;
            return out;
        }
        for (;;) {
            this.skipWs();
            out.push(this.parseValue(depth + 1));
            this.skipWs();
            const ch = this.text[this.pos++];
            if (ch === ',') {
                continue;
            }
            if (ch === ']') {
                return out;
            }
            this.pos--;
            this.fail('expected , or ]');
        }
    }

    parseObject(depth) {
        this.pos++; // {
        const out = {};
        this.skipWs();
        if (this.text[this.pos] === '}') {
            this.pos++;
            return out;
        }
        for (;;) {
            this.skipWs();
            if (this.text[this.pos] !== '"') {
                this.fail('expected string key');
            }
            const key = this.parseString();
            this.skipWs();
            if (this.text[this.pos++] !== ':') {
                this.pos--;
                this.fail('expected :');
            }
            this.skipWs();
            const value = this.parseValue(depth + 1);
            if (Object.prototype.hasOwnProperty.call(out, key)) {
                throw new CanonicalizationError(`duplicate object key "${key}"`);
            }
            // defineProperty creates an own data property even for "__proto__",
            // where plain assignment would invoke the prototype setter instead.
            Object.defineProperty(out, key, {
                value,
                enumerable: true,
                writable: true,
                configurable: true
            });
            this.skipWs();
            const ch = this.text[this.pos++];
            if (ch === ',') {
                continue;
            }
            if (ch === '}') {
                return out;
            }
            this.pos--;
            this.fail('expected , or }');
        }
    }
}

/**
 * Core SchemaPin operations for schema canonicalization and hashing.
 */
export class SchemaPinCore {
    /**
     * Parse JSON text strictly for canonicalization.
     *
     * Rejects (`CanonicalizationError`): duplicate object keys,
     * `NaN`/`Infinity`, numbers outside the 2**53-1 safe range, lone
     * surrogates and unescaped control characters. `__proto__` keys are
     * preserved as own properties.
     *
     * @param {string} text
     * @returns {*}
     */
    static parseSchemaJson(text) {
        if (typeof text !== 'string') {
            throw new CanonicalizationError('input must be a string');
        }
        return new StrictParser(text).parseDocument();
    }

    /**
     * Convert a schema to its `schemapin-v1` canonical string.
     *
     * @param {*} schema - Tool schema (object, array or primitive)
     * @returns {string} Canonical string representation
     * @throws {CanonicalizationError} when the value has no canonical form
     */
    static canonicalizeSchema(schema) {
        if (schema === undefined) {
            throw new CanonicalizationError('undefined has no canonical form');
        }
        return canonicalValue(schema, 0);
    }

    /**
     * Hash canonical schema string using SHA-256.
     *
     * @param {string} canonical - Canonical schema string
     * @returns {Buffer} SHA-256 hash bytes
     */
    static hashCanonical(canonical) {
        return createHash('sha256').update(canonical, 'utf8').digest();
    }

    /**
     * Convenience method to canonicalize and hash schema in one step.
     *
     * @param {*} schema - Tool schema as object
     * @returns {Buffer} SHA-256 hash of canonical schema
     */
    static canonicalizeAndHash(schema) {
        const canonical = this.canonicalizeSchema(schema);
        return this.hashCanonical(canonical);
    }
}
