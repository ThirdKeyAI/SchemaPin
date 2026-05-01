/**
 * DNS TXT cross-verification for SchemaPin v1.4.
 *
 * A tool provider MAY publish a TXT record at `_schemapin.{domain}` containing
 * the public-key fingerprint advertised in `.well-known/schemapin.json`. When
 * present, clients use it as a *second-channel* verification: the DNS
 * credential chain is independent of the HTTPS hosting credential chain, so
 * compromising one does not compromise the other.
 *
 * ## TXT record format
 *
 * ```
 * _schemapin.example.com. IN TXT "v=schemapin1; kid=acme-2026-01; fp=sha256:a1b2c3..."
 * ```
 *
 * Fields:
 * - `v` - version tag (`schemapin1`); required
 * - `fp` - key fingerprint (`sha256:<hex>`); required, lowercase hex
 * - `kid` - optional key id, used for disambiguating multi-key endpoints
 *
 * ## Verification semantics
 *
 * - **Absent record** -> no effect (DNS TXT is optional)
 * - **Present and matching** -> confidence boost
 * - **Present and mismatching** -> hard failure with `DOMAIN_MISMATCH`
 *
 * Use {@link parseTxtRecord} to parse a raw TXT string and {@link verifyDnsMatch}
 * to cross-check it against a discovery document. {@link fetchDnsTxt} performs
 * the actual DNS lookup using Node's built-in `node:dns/promises`.
 */

import { resolveTxt } from 'node:dns/promises';
import { KeyManager } from './crypto.js';

/**
 * Parsed `_schemapin.{domain}` TXT record.
 *
 * @typedef {Object} DnsTxtRecord
 * @property {string} version
 * @property {string|null} kid
 * @property {string} fingerprint - Lowercase fingerprint string, including
 *   the `sha256:` prefix.
 */

/**
 * Parse a raw TXT record value
 * (e.g. `"v=schemapin1; kid=acme-2026-01; fp=sha256:..."`).
 *
 * Whitespace around `;` and `=` is tolerated. Field order is not significant.
 * Unknown fields are ignored (forward-compat). Throws on malformed input.
 *
 * @param {string} value - Raw TXT value
 * @returns {DnsTxtRecord} Parsed record
 * @throws {Error} If required fields are missing or version is unsupported
 */
export function parseTxtRecord(value) {
    let version = null;
    let kid = null;
    let fingerprint = null;

    for (const rawPart of value.split(';')) {
        const part = rawPart.trim();
        if (part.length === 0) {
            continue;
        }
        const eqIdx = part.indexOf('=');
        if (eqIdx === -1) {
            throw new Error(`DNS TXT field missing '=': ${part}`);
        }
        const k = part.slice(0, eqIdx).trim().toLowerCase();
        const v = part.slice(eqIdx + 1).trim();
        if (k === 'v') {
            version = v;
        } else if (k === 'kid') {
            kid = v;
        } else if (k === 'fp') {
            fingerprint = v.toLowerCase();
        }
        // Forward-compat: ignore unknown fields rather than reject.
    }

    if (version === null) {
        throw new Error('DNS TXT record missing required \'v\' field');
    }
    if (version !== 'schemapin1') {
        throw new Error(`DNS TXT unsupported version: ${version}`);
    }
    if (fingerprint === null) {
        throw new Error('DNS TXT record missing required \'fp\' field');
    }
    if (!fingerprint.startsWith('sha256:')) {
        throw new Error(`DNS TXT 'fp' must be sha256:<hex>: ${fingerprint}`);
    }

    return { version, kid, fingerprint };
}

/**
 * Cross-check the DNS TXT record's fingerprint against the discovery document.
 *
 * Computes the SHA-256 fingerprint of `discovery.public_key_pem` and compares
 * it (case-insensitively) against `txt.fingerprint`. Throws on mismatch.
 *
 * @param {Object} discovery - Well-known discovery document
 * @param {DnsTxtRecord} txt - Parsed TXT record
 * @throws {Error} If the fingerprints do not match
 */
export function verifyDnsMatch(discovery, txt) {
    if (!discovery || !discovery.public_key_pem) {
        throw new Error('DNS TXT verify: discovery missing public_key_pem');
    }
    const computed = KeyManager.calculateKeyFingerprint(discovery.public_key_pem).toLowerCase();
    if (computed !== txt.fingerprint) {
        throw new Error(
            `DNS TXT fingerprint mismatch: discovery=${computed}, dns=${txt.fingerprint}`
        );
    }
}

/**
 * Construct the DNS lookup name for a given tool domain.
 *
 * @param {string} domain - Tool domain (e.g. `example.com` or `example.com.`)
 * @returns {string} DNS name (e.g. `_schemapin.example.com`)
 */
export function txtRecordName(domain) {
    return `_schemapin.${domain.replace(/\.$/, '')}`;
}

/**
 * Fetch and parse the `_schemapin.{domain}` TXT record.
 *
 * Returns:
 * - `{ version, kid, fingerprint }` - record present and parseable
 * - `null` - no `_schemapin` TXT record exists for the domain
 *
 * Throws on other resolution errors. Multiple matching TXT chunks are joined
 * per RFC 1464 (concatenation in emit order). Multiple separate TXT records
 * at the same name are not supported - the first valid `v=schemapin1` record
 * wins.
 *
 * @param {string} domain - Tool domain
 * @returns {Promise<DnsTxtRecord|null>}
 */
export async function fetchDnsTxt(domain) {
    const name = txtRecordName(domain);
    let records;
    try {
        records = await resolveTxt(name);
    } catch (err) {
        // `resolveTxt` throws an error with `code` = 'ENOTFOUND' / 'ENODATA'
        // when no TXT record exists. Treat both as "absent".
        if (err && (err.code === 'ENOTFOUND' || err.code === 'ENODATA')) {
            return null;
        }
        throw new Error(`DNS TXT lookup failed for ${name}: ${err.message ?? err}`);
    }

    for (const chunks of records) {
        // RFC 1464: a single TXT record may be split across multiple
        // <character-strings>; node returns these as inner string arrays.
        const joined = chunks.join('');
        if (joined.includes('v=schemapin1')) {
            return parseTxtRecord(joined);
        }
    }
    return null;
}
