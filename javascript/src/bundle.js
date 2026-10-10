/**
 * Trust bundles for offline/air-gapped SchemaPin verification.
 *
 * v1.4 (A2A trust-bundle distribution): a *bundle authority* can sign a trust
 * bundle so it can be exchanged between agents over A2A without per-bundle
 * out-of-band trust establishment. This module provides:
 *
 * - {@link signTrustBundle} / {@link verifyTrustBundle} — ECDSA P-256 over the
 *   canonical bundle bytes, with TOFU pinning of the authority key by `kid`.
 * - {@link mergeTrustBundles} — combine bundles from multiple sources, newest
 *   entry wins per domain.
 * - {@link buildTrustBundleRequest} / {@link buildTrustBundleResponse} /
 *   {@link parseTrustBundleResponse} — the `schemapin/trustBundle` JSON-RPC
 *   envelope for A2A bundle exchange.
 *
 * ## Signing input
 *
 * The signature covers the `schemapin-v1` canonicalization (recursive sorted
 * keys, compact, UTF-8) of the entire bundle object with the `signature` field
 * set to the empty string `""`. All four SDKs build the identical byte string,
 * so a bundle signed by any SDK verifies in every other.
 */

import { createPublicKey } from 'crypto';
import { SchemaPinCore } from './core.js';
import { KeyManager, SignatureManager } from './crypto.js';
import { ErrorCode, parseRfc3339 } from './verification.js';

/** Bundle-distribution wire format version stamped on signed bundles. */
export const BUNDLE_VERSION_SIGNED = '1.4';

/**
 * Sentinel "domain" used to key bundle-authority pins in a {@link KeyPinStore}.
 * Authorities are pinned by `kid`, independent of any tool domain.
 */
export const BUNDLE_AUTHORITY_PIN_DOMAIN = '_bundle_authority';

/**
 * Build a verification-style Error carrying a structured `.code`.
 *
 * @param {string} code - One of {@link ErrorCode}
 * @param {string} message
 * @returns {Error}
 */
function bundleError(code, message) {
    const err = new Error(message);
    err.code = code;
    return err;
}

const DOCUMENT_OPTIONAL_FIELDS = ['developer_name', 'contact', 'revocation_endpoint'];

/**
 * Project a bundled discovery entry onto the signed field set (mirrors the
 * Rust serde output: optional strings omitted when absent, `revoked_keys`
 * always present).
 */
function normalizeDocument(doc) {
    const out = {
        domain: doc.domain ?? '',
        schema_version: doc.schema_version ?? '',
        public_key_pem: doc.public_key_pem ?? '',
        revoked_keys: Array.isArray(doc.revoked_keys) ? [...doc.revoked_keys] : []
    };
    for (const key of DOCUMENT_OPTIONAL_FIELDS) {
        if (doc[key] !== null && doc[key] !== undefined) {
            out[key] = doc[key];
        }
    }
    return out;
}

function normalizeRevocation(rev) {
    return {
        schemapin_version: rev.schemapin_version ?? '',
        domain: rev.domain ?? '',
        updated_at: rev.updated_at ?? '',
        revoked_keys: (rev.revoked_keys ?? []).map((k) => ({
            fingerprint: k.fingerprint,
            revoked_at: k.revoked_at,
            reason: k.reason
        }))
    };
}

/**
 * Build the canonical bytes that a bundle's signature covers: the bundle's
 * known fields (unknown fields are ignored and therefore unprotected) with
 * `signature` forced to `""`, `schemapin-v1`-canonicalized.
 *
 * @param {Object} bundle
 * @returns {string} Canonical JSON string
 */
function signingBytes(bundle) {
    const obj = {
        schemapin_bundle_version: bundle.schemapin_bundle_version,
        created_at: bundle.created_at,
        documents: (bundle.documents ?? []).map(normalizeDocument),
        revocations: (bundle.revocations ?? []).map(normalizeRevocation)
    };
    if (bundle.bundle_authority) {
        obj.bundle_authority = { kid: bundle.bundle_authority.kid, public_key_pem: bundle.bundle_authority.public_key_pem };
    }
    if (bundle.signed_at !== null && bundle.signed_at !== undefined) {
        obj.signed_at = bundle.signed_at;
    }
    if (bundle.expires_at !== null && bundle.expires_at !== undefined) {
        obj.expires_at = bundle.expires_at;
    }
    obj.signature = '';
    return SchemaPinCore.canonicalizeSchema(obj);
}

/**
 * @param {Object} bundle
 * @returns {string|null} a domain that appears more than once, or null
 */
export function findDuplicateDomain(bundle) {
    for (const list of [bundle.documents ?? [], bundle.revocations ?? []]) {
        const seen = new Set();
        for (const entry of list) {
            if (seen.has(entry.domain)) {
                return entry.domain;
            }
            seen.add(entry.domain);
        }
    }
    return null;
}

/**
 * Pre-seed the expected fingerprint (`sha256:<hex>`) of a bundle authority.
 * This is the allow-list entry {@link verifyTrustBundle} requires.
 *
 * @param {import('./verification.js').KeyPinStore} store
 * @param {string} kid
 * @param {string} fingerprint
 */
export function seedBundleAuthority(store, kid, fingerprint) {
    store.seed(kid, BUNDLE_AUTHORITY_PIN_DOMAIN, fingerprint);
}

/**
 * Seed an authority from its PEM public key (for example the `public_key_pem`
 * of the authority's own discovery document). Returns the fingerprint.
 *
 * @param {import('./verification.js').KeyPinStore} store
 * @param {string} kid
 * @param {string} publicKeyPem
 * @returns {string}
 */
export function seedBundleAuthorityFromPem(store, kid, publicKeyPem) {
    const fingerprint = KeyManager.calculateKeyFingerprint(publicKeyPem);
    seedBundleAuthority(store, kid, fingerprint);
    return fingerprint;
}

/**
 * Create an empty trust bundle.
 *
 * @param {string} createdAt - ISO 8601 timestamp
 * @returns {Object} Trust bundle
 */
export function createTrustBundle(createdAt) {
    return {
        schemapin_bundle_version: '1.2',
        created_at: createdAt,
        documents: [],
        revocations: []
    };
}

/**
 * Create a flattened BundledDiscovery entry.
 * Merges domain with well-known fields at the same level.
 *
 * @param {string} domain - The domain
 * @param {Object} wellKnown - Well-known response fields
 * @returns {Object} Flattened bundled discovery entry
 */
export function createBundledDiscovery(domain, wellKnown) {
    return { domain, ...wellKnown };
}

/**
 * Find a discovery document in a bundle for a domain.
 *
 * @param {Object} bundle - Trust bundle
 * @param {string} domain - Domain to search for
 * @returns {Object|null} Well-known fields (without 'domain' key), or null
 */
export function findDiscovery(bundle, domain) {
    for (const doc of bundle.documents) {
        if (doc.domain === domain) {
            const { domain: _, ...rest } = doc;
            return rest;
        }
    }
    return null;
}

/**
 * Find a revocation document in a bundle for a domain.
 *
 * @param {Object} bundle - Trust bundle
 * @param {string} domain - Domain to search for
 * @returns {Object|null} Revocation document or null
 */
export function findRevocation(bundle, domain) {
    for (const rev of bundle.revocations) {
        if (rev.domain === domain) {
            return rev;
        }
    }
    return null;
}

/**
 * Parse a trust bundle from a JSON string.
 *
 * @param {string} jsonStr - JSON string
 * @returns {Object} Trust bundle
 */
export function parseTrustBundle(jsonStr) {
    return JSON.parse(jsonStr);
}

// ─────────────────────────────────────────────────────────────────────────
// v1.4 — A2A trust-bundle distribution
// ─────────────────────────────────────────────────────────────────────────

/**
 * Sign a trust bundle with a bundle-authority key.
 *
 * Stamps `bundle_authority` (derived public key + `kid`),
 * `schemapin_bundle_version = "1.4"`, `signed_at`, and optional `expires_at`,
 * then writes the base64 DER ECDSA P-256 `signature`. `signedAt` / `expiresAt`
 * are caller-supplied RFC 3339 strings (kept out of the core so signing is
 * deterministic and cross-language testable).
 *
 * @param {Object} bundle - Trust bundle to sign
 * @param {string} privateKeyPem - PEM-encoded ECDSA P-256 private key
 * @param {string} kid - Bundle authority key id
 * @param {string} signedAt - RFC 3339 timestamp
 * @param {string|null} [expiresAt=null] - Optional RFC 3339 expiry
 * @returns {Object} Signed trust bundle
 */
export function signTrustBundle(bundle, privateKeyPem, kid, signedAt, expiresAt = null) {
    const dup = findDuplicateDomain(bundle);
    if (dup !== null) {
        throw new Error(`trust bundle has duplicate entries for domain ${JSON.stringify(dup)}`);
    }
    // Derive the authority public key PEM from the private key.
    const publicKeyPem = createPublicKey(privateKeyPem)
        .export({ type: 'spki', format: 'pem' });

    // Build the signed bundle, omitting absent optional fields so the
    // canonical form matches the Rust reference exactly.
    const signed = {
        schemapin_bundle_version: BUNDLE_VERSION_SIGNED,
        created_at: bundle.created_at,
        documents: bundle.documents ? [...bundle.documents] : [],
        revocations: bundle.revocations ? [...bundle.revocations] : [],
        bundle_authority: { kid, public_key_pem: publicKeyPem },
        signed_at: signedAt
    };
    if (expiresAt !== null && expiresAt !== undefined) {
        signed.expires_at = expiresAt;
    }

    const canonical = signingBytes(signed);
    signed.signature = SignatureManager.signHash(
        Buffer.from(canonical, 'utf8'),
        privateKeyPem
    );
    return signed;
}

/**
 * Verify a signed trust bundle against the authority allow-list.
 *
 * Steps: require `bundle_authority` + `signature` (else `BUNDLE_UNSIGNED`);
 * reject duplicate domains (`DISCOVERY_INVALID`); reject when `expires_at`
 * is in the past or not strict RFC 3339 (`BUNDLE_EXPIRED`); look the
 * authority's key fingerprint up by `kid` -- a different pinned key is
 * `KEY_PIN_MISMATCH`, an unknown `kid` is `BUNDLE_AUTHORITY_UNTRUSTED`
 * unless `allowFirstUse` is true; verify the signature over the canonical
 * bytes (`SIGNATURE_INVALID`); pin the authority on first use only after the
 * signature verified.
 *
 * The bundle carries its own public key, so without an allow-list any
 * self-signed bundle under a fresh `kid` would pass. Seed expected
 * authorities with {@link seedBundleAuthority}; treat `allowFirstUse`
 * exactly like TOFU for a tool key (prompt the user, log it).
 *
 * @param {Object} bundle - Signed trust bundle
 * @param {import('./verification.js').KeyPinStore} authorityPinStore
 * @param {boolean} [allowFirstUse=false]
 * @returns {{ kid: string, fingerprint: string, first_use: boolean }}
 * @throws {Error} With `.code` set to the relevant {@link ErrorCode}
 */
export function verifyTrustBundle(bundle, authorityPinStore, allowFirstUse = false) {
    const authority = bundle.bundle_authority;
    if (!authority) {
        throw bundleError(ErrorCode.BUNDLE_UNSIGNED, 'trust bundle has no bundle_authority');
    }
    const signature = bundle.signature;
    if (!signature) {
        throw bundleError(ErrorCode.BUNDLE_UNSIGNED, 'trust bundle has no signature');
    }

    const dup = findDuplicateDomain(bundle);
    if (dup !== null) {
        throw bundleError(ErrorCode.DISCOVERY_INVALID, `trust bundle has duplicate entries for domain ${JSON.stringify(dup)}`);
    }

    if (bundle.expires_at !== null && bundle.expires_at !== undefined) {
        const exp = parseRfc3339(bundle.expires_at);
        if (exp === null) {
            throw bundleError(
                ErrorCode.BUNDLE_EXPIRED,
                `unparseable expires_at '${bundle.expires_at}'`
            );
        }
        if (Date.now() > exp) {
            throw bundleError(
                ErrorCode.BUNDLE_EXPIRED,
                `trust bundle expired at ${bundle.expires_at}`
            );
        }
    }

    let fingerprint;
    try {
        fingerprint = KeyManager.calculateKeyFingerprint(authority.public_key_pem);
    } catch (e) {
        throw bundleError(ErrorCode.KEY_NOT_FOUND, `bundle authority key is invalid: ${e.message}`);
    }
    const pinResult = authorityPinStore.check(authority.kid, BUNDLE_AUTHORITY_PIN_DOMAIN, fingerprint);
    if (pinResult === 'changed') {
        throw bundleError(
            ErrorCode.KEY_PIN_MISMATCH,
            `bundle authority key for kid '${authority.kid}' does not match the seeded authority key`
        );
    }
    if (pinResult === 'first_use' && !allowFirstUse) {
        throw bundleError(
            ErrorCode.BUNDLE_AUTHORITY_UNTRUSTED,
            `bundle authority kid '${authority.kid}' is not in the authority allow-list; seed it with seedBundleAuthority() or pass allowFirstUse`
        );
    }

    const canonical = signingBytes(bundle);
    const valid = SignatureManager.verifySignature(
        Buffer.from(canonical, 'utf8'),
        signature,
        authority.public_key_pem
    );
    if (!valid) {
        throw bundleError(
            ErrorCode.SIGNATURE_INVALID,
            'trust bundle signature does not verify'
        );
    }
    if (pinResult === 'first_use') {
        authorityPinStore.pin(authority.kid, BUNDLE_AUTHORITY_PIN_DOMAIN, fingerprint);
    }
    return { kid: authority.kid, fingerprint, first_use: pinResult === 'first_use' };
}

/**
 * Rank used by {@link mergeTrustBundles}: higher wins.
 *
 * @returns {[number, number]} [authority precedence, parsed timestamp ms]
 */
function mergeRank(bundle, precedence) {
    const kid = bundle.bundle_authority?.kid ?? null;
    let rank = 0;
    if (precedence && precedence.length > 0) {
        rank = -precedence.length - 1;
        const idx = kid === null ? -1 : precedence.indexOf(kid);
        if (idx >= 0) {
            rank = -idx;
        }
    }
    const ts = parseRfc3339(bundle.signed_at ?? bundle.created_at ?? '');
    return [rank, ts === null ? Number.NEGATIVE_INFINITY : ts];
}

function rankGreater(a, b) {
    return a[0] > b[0] || (a[0] === b[0] && a[1] > b[1]);
}

/**
 * Merge trust bundles, deduplicating discovery + revocation documents by
 * domain.
 *
 * When two bundles carry the same domain the winner is chosen by
 * `authorityPrecedence` first (a list of authority `kid` values, earlier
 * wins; bundles from unlisted or absent authorities rank last) and by the
 * newer **parsed** RFC 3339 timestamp (`signed_at`, else `created_at`)
 * second. Unparseable timestamps rank oldest, so a bundle cannot win a merge
 * by claiming a bogus future date. Merge only bundles you have already
 * verified with {@link verifyTrustBundle}.
 *
 * The result is an *unsigned* bundle stamped `schemapin_bundle_version =
 * "1.4"` with `created_at` set to the newest source timestamp. Re-sign it
 * with {@link signTrustBundle} before redistribution.
 *
 * @param {Object[]} bundles
 * @param {string[]|null} [authorityPrecedence=null]
 * @returns {Object} Merged unsigned trust bundle
 */
export function mergeTrustBundles(bundles, authorityPrecedence = null) {
    const docs = new Map();
    const revs = new Map();
    let newest = null;
    let newestRaw = '';

    for (const b of bundles) {
        const rank = mergeRank(b, authorityPrecedence);
        if (newest === null || rank[1] > newest) {
            newest = rank[1];
            newestRaw = b.signed_at ?? b.created_at ?? '';
        }
        for (const d of b.documents ?? []) {
            const existing = docs.get(d.domain);
            if (!existing || rankGreater(rank, existing.rank)) {
                docs.set(d.domain, { rank, doc: d });
            }
        }
        for (const r of b.revocations ?? []) {
            const existing = revs.get(r.domain);
            if (!existing || rankGreater(rank, existing.rank)) {
                revs.set(r.domain, { rank, doc: r });
            }
        }
    }

    const byDomain = (a, b) => (a.domain < b.domain ? -1 : a.domain > b.domain ? 1 : 0);
    const documents = [...docs.values()].map((e) => e.doc).sort(byDomain);
    const revocations = [...revs.values()].map((e) => e.doc).sort(byDomain);

    return {
        schemapin_bundle_version: BUNDLE_VERSION_SIGNED,
        created_at: newestRaw,
        documents,
        revocations
    };
}

/**
 * Build a `schemapin/trustBundle` JSON-RPC request. `domain` optionally scopes
 * the request to a single provider; omit (null) for "send your whole bundle".
 *
 * @param {string|null} domain
 * @param {number|string} id - JSON-RPC request id
 * @returns {Object} JSON-RPC request envelope
 */
export function buildTrustBundleRequest(domain, id) {
    const params = (domain !== null && domain !== undefined) ? { domain } : {};
    return {
        jsonrpc: '2.0',
        method: 'schemapin/trustBundle',
        params,
        id
    };
}

/**
 * Build a `schemapin/trustBundle` JSON-RPC response carrying a bundle.
 *
 * @param {Object} bundle
 * @param {number|string} id - JSON-RPC response id
 * @returns {Object} JSON-RPC response envelope
 */
export function buildTrustBundleResponse(bundle, id) {
    return {
        jsonrpc: '2.0',
        result: { bundle },
        id
    };
}

/**
 * Extract the bundle from a `schemapin/trustBundle` JSON-RPC response.
 *
 * @param {Object} response - JSON-RPC response envelope
 * @returns {Object} Trust bundle
 * @throws {Error} With `.code = DISCOVERY_INVALID` when `result.bundle` absent
 */
export function parseTrustBundleResponse(response) {
    const bundle = response?.result?.bundle;
    if (bundle === undefined || bundle === null) {
        throw bundleError(
            ErrorCode.DISCOVERY_INVALID,
            'JSON-RPC response missing result.bundle'
        );
    }
    return bundle;
}
