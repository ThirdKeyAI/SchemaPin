# Trust Bundle Distribution for A2A Networks

> **Status:** v1.4.0-alpha.4 — implemented in **Rust, Python, JavaScript, and Go**. A bundle signed by any one SDK verifies in every other (proven by the shared `tests/cross-language/signed_bundle.json` fixture).

A [trust bundle](trust-bundles.md) pre-packages discovery and revocation documents for offline verification. Until v1.4 a bundle had no authenticity of its own — you had to trust however it reached you. That is fine for a bundle you build and ship yourself, but not for one an agent hands to another agent over A2A.

v1.4 lets a **bundle authority** sign a trust bundle so it can be exchanged between agents without per-bundle out-of-band trust establishment. The receiving agent verifies the signature and TOFU-pins the authority key by `kid`, exactly as it would pin a tool's signing key.

All additions are optional fields — an unsigned bundle is byte-for-byte what it was before v1.4, and v1.2/v1.3 consumers ignore the new fields.

---

## Wire format

A signed bundle gains four optional top-level fields:

```json
{
  "schemapin_bundle_version": "1.4",
  "created_at": "2026-05-15T00:00:00Z",
  "documents": [ /* ... */ ],
  "revocations": [ /* ... */ ],
  "bundle_authority": {
    "kid": "schemapin-bundle-authority-2026",
    "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
  },
  "signed_at": "2026-05-15T00:00:00Z",
  "expires_at": "2099-01-01T00:00:00Z",
  "signature": "MEUCIQ..."
}
```

- **`bundle_authority`** — the authority that signed the bundle. The public key is carried as `public_key_pem` (consistent with discovery documents), so the bundle is self-verifying.
- **`signed_at`** / **`expires_at`** — RFC 3339 timestamps. `expires_at` is optional even on a signed bundle; when present and past, verification fails with `BUNDLE_EXPIRED`.
- **`signature`** — base64 DER ECDSA P-256 signature.

Signing stamps `schemapin_bundle_version` to `"1.4"`.

### Signing input

The signature covers the **`schemapin-v1` canonicalization** (recursive sorted keys, compact separators, UTF-8) of the entire bundle object with the `signature` field set to the empty string `""`. This is the same canonicalization used for schema and skill signing, so all four SDKs produce the identical byte string and cross-verify.

---

## Operations

| Operation | Purpose |
|-----------|---------|
| `sign_trust_bundle(bundle, private_key_pem, kid, signed_at, expires_at?)` | Stamp authority metadata and write the signature. Derives the authority public key from the private key. |
| `verify_trust_bundle(bundle, authority_pin_store)` | Verify the signature, reject expired bundles, and TOFU-pin the authority key by `kid`. |
| `merge_trust_bundles(bundles)` | Combine bundles from multiple sources, deduplicating by domain (newest wins). Returns an **unsigned** bundle to re-sign before redistribution. |
| `build_trust_bundle_request` / `build_trust_bundle_response` / `parse_trust_bundle_response` | `schemapin/trustBundle` JSON-RPC envelope helpers for A2A exchange. |

(Function names are camel/Pascal-cased per language — e.g. `signTrustBundle` in JS, `SignTrustBundle` in Go.)

### Verification steps

`verify_trust_bundle` runs:

1. Require `bundle_authority` and `signature` — else `BUNDLE_UNSIGNED`.
2. If `expires_at` is present and in the past (or unparseable) — `BUNDLE_EXPIRED`.
3. TOFU-pin the authority key fingerprint by `kid`. A different key reusing a pinned `kid` — an impersonation attempt — fails with `KEY_PIN_MISMATCH`.
4. Verify the signature over the canonical bytes — failure is `SIGNATURE_INVALID`.

---

## Example (Rust)

```rust
use schemapin::bundle::{sign_trust_bundle, verify_trust_bundle, merge_trust_bundles};
use schemapin::pinning::KeyPinStore;

// Authority signs a bundle for distribution.
let signed = sign_trust_bundle(
    &bundle,
    &authority_private_pem,
    "schemapin-bundle-authority-2026",
    "2026-05-15T00:00:00Z",
    Some("2026-08-15T00:00:00Z"),
)?;

// A receiving agent verifies it and TOFU-pins the authority.
let mut authorities = KeyPinStore::new();
verify_trust_bundle(&signed, &mut authorities)?;

// Combine bundles from several sources before re-signing.
let merged = merge_trust_bundles(&[signed, other_signed]);
```

The JSON-RPC helpers produce the `schemapin/trustBundle` message envelope; the
transport and the receiving pin-store update are the host application's
responsibility (e.g. a Symbiont coordinator receiving the message over A2A).

---

## Key rotation

The bundle authority is a long-lived signing key. To rotate it, sign new
bundles under a new `kid` and distribute the new authority public key through
the same channel you bootstrap any first-use key. Verifiers TOFU-pin per `kid`,
so a new `kid` is a first-use pin, not a mismatch.

See [Technical specification](https://github.com/ThirdKeyAI/SchemaPin/blob/main/TECHNICAL_SPECIFICATION.md) for the normative definition.
