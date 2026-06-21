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
import { ErrorCode } from './verification.js';

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

/**
 * Build the canonical bytes that a bundle's signature covers: the bundle with
 * its `signature` field forced to `""`, `schemapin-v1`-canonicalized.
 *
 * @param {Object} bundle
 * @returns {string} Canonical JSON string
 */
function signingBytes(bundle) {
    const obj = { ...bundle, signature: '' };
    return SchemaPinCore.canonicalizeSchema(obj);
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
 * Verify a signed trust bundle and TOFU-pin its authority key by `kid`.
 *
 * Steps: require `bundle_authority` + `signature` (else `BUNDLE_UNSIGNED`);
 * reject when `expires_at` is in the past or unparseable (`BUNDLE_EXPIRED`);
 * TOFU-pin the authority's key fingerprint by `kid` (mismatch →
 * `KEY_PIN_MISMATCH`); verify the signature over the canonical bytes
 * (failure → `SIGNATURE_INVALID`).
 *
 * @param {Object} bundle - Signed trust bundle
 * @param {import('./verification.js').KeyPinStore} authorityPinStore
 * @returns {boolean} `true` on success
 * @throws {Error} With `.code` set to the relevant {@link ErrorCode}
 */
export function verifyTrustBundle(bundle, authorityPinStore) {
    const authority = bundle.bundle_authority;
    if (!authority) {
        throw bundleError(ErrorCode.BUNDLE_UNSIGNED, 'trust bundle has no bundle_authority');
    }
    const signature = bundle.signature;
    if (!signature) {
        throw bundleError(ErrorCode.BUNDLE_UNSIGNED, 'trust bundle has no signature');
    }

    if (bundle.expires_at !== null && bundle.expires_at !== undefined) {
        const exp = new Date(bundle.expires_at);
        if (Number.isNaN(exp.getTime())) {
            throw bundleError(
                ErrorCode.BUNDLE_EXPIRED,
                `unparseable expires_at '${bundle.expires_at}'`
            );
        }
        if (Date.now() > exp.getTime()) {
            throw bundleError(
                ErrorCode.BUNDLE_EXPIRED,
                `trust bundle expired at ${bundle.expires_at}`
            );
        }
    }

    const fingerprint = KeyManager.calculateKeyFingerprint(authority.public_key_pem);
    const pinResult = authorityPinStore.checkAndPin(
        authority.kid,
        BUNDLE_AUTHORITY_PIN_DOMAIN,
        fingerprint
    );
    if (pinResult === 'changed') {
        throw bundleError(
            ErrorCode.KEY_PIN_MISMATCH,
            `bundle authority key for kid '${authority.kid}' changed since last use`
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
    return true;
}

/**
 * Merge trust bundles, deduplicating discovery + revocation documents by
 * domain. When two bundles carry the same domain, the entry from the bundle
 * with the newer timestamp (`signed_at`, else `created_at`) wins.
 *
 * The result is an *unsigned* bundle (a merge cannot carry a single
 * authority's signature) stamped `schemapin_bundle_version = "1.4"` with
 * `created_at` set to the newest source timestamp. Re-sign it with
 * {@link signTrustBundle} before redistribution. Documents and revocations are
 * sorted by domain.
 *
 * @param {Object[]} bundles
 * @returns {Object} Merged unsigned trust bundle
 */
export function mergeTrustBundles(bundles) {
    // domain -> { ts, doc }
    const docs = new Map();
    const revs = new Map();
    let newestTs = '';

    for (const b of bundles) {
        const ts = b.signed_at ?? b.created_at ?? '';
        if (ts > newestTs) {
            newestTs = ts;
        }
        for (const d of b.documents ?? []) {
            const existing = docs.get(d.domain);
            if (!existing || existing.ts < ts) {
                docs.set(d.domain, { ts, doc: d });
            }
        }
        for (const r of b.revocations ?? []) {
            const existing = revs.get(r.domain);
            if (!existing || existing.ts < ts) {
                revs.set(r.domain, { ts, doc: r });
            }
        }
    }

    const documents = [...docs.values()]
        .map((e) => e.doc)
        .sort((a, b) => (a.domain < b.domain ? -1 : a.domain > b.domain ? 1 : 0));
    const revocations = [...revs.values()]
        .map((e) => e.doc)
        .sort((a, b) => (a.domain < b.domain ? -1 : a.domain > b.domain ? 1 : 0));

    return {
        schemapin_bundle_version: BUNDLE_VERSION_SIGNED,
        created_at: newestTs,
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
