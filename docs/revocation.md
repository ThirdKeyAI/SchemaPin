# Revocation

When a private key is compromised, retired, or superseded, you need a way to tell every client that has previously pinned that key to stop trusting it. SchemaPin supports two complementary mechanisms:

1. **Inline `revoked_keys`** — an array on the `.well-known/schemapin.json` discovery document. Cheap, requires no extra endpoint, but only suitable for a handful of revocations.
2. **Standalone revocation document** — a separate, signed JSON document at a dedicated endpoint. Scales to many revocations, can be cached aggressively, and supports structured reasons. This is the SchemaPin v1.2 approach.

Both mechanisms are checked together — see [Combined revocation checking](#combined-revocation-checking) below.

> **TL;DR**
> - Compute the SHA-256 fingerprint of the public key you want to revoke.
> - Add it to either `revoked_keys` in `.well-known/schemapin.json` **or** to a standalone revocation document at a stable URL.
> - Clients fail closed on any pin matching a revoked fingerprint.

---

## Key fingerprints

Every revocation entry is keyed by the SHA-256 fingerprint of the **DER-encoded SubjectPublicKeyInfo** of the key (the same bytes that sit between the `-----BEGIN PUBLIC KEY-----` / `-----END PUBLIC KEY-----` markers, base64-decoded).

The canonical form is `sha256:<lowercase-hex>`:

```
sha256:9e2af70c31bb48d65a11e9c47f0add42c4118add370f6eb925e24bf09133ac7a
```

Compute it from a PEM file:

```bash
# OpenSSL
openssl pkey -pubin -in pubkey.pem -outform DER \
  | openssl dgst -sha256 -hex \
  | awk '{print "sha256:" $2}'
```

Or programmatically:

| Language | Helper |
|----------|--------|
| Python | `from schemapin.crypto import KeyManager; KeyManager.calculate_key_fingerprint(public_key_pem)` |
| JavaScript | `import { calculateKeyFingerprint } from 'schemapin'; calculateKeyFingerprint(publicKeyPem)` |
| Go | `crypto.CalculateKeyID(publicKeyPEM)` |
| Rust | `schemapin::crypto::calculate_key_id(&public_key_pem)?` |

---

## Mechanism 1: Inline `revoked_keys`

Add the fingerprints to your discovery document. v1.0 clients understand this format.

```json
{
  "schema_version": "1.2",
  "developer_name": "Acme Tools",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "revoked_keys": [
    "sha256:9e2af70c31bb48d65a11e9c47f0add42c4118add370f6eb925e24bf09133ac7a",
    "sha256:c4118add370f6eb925e24bf09133ac7a9e2af70c31bb48d65a11e9c47f0add42"
  ],
  "contact": "security@example.com"
}
```

**Use this when**: you have one or two retired keys and don't expect to add many more.

**Don't use this when**: you anticipate dozens of revocations, or you need structured metadata (reason, timestamp). Use a standalone document instead.

---

## Mechanism 2: Standalone Revocation Document (v1.2+)

Publish a separate signed JSON document at a stable URL — typically `/.well-known/schemapin-revocations.json`. Reference it from your discovery document via `revocation_endpoint`:

```json
{
  "schema_version": "1.2",
  "developer_name": "Acme Tools",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "revocation_endpoint": "https://example.com/.well-known/schemapin-revocations.json",
  "contact": "security@example.com"
}
```

The revocation document itself looks like this:

```json
{
  "schema_version": "1.2",
  "domain": "example.com",
  "issued_at": "2026-04-30T08:00:00Z",
  "revoked_keys": [
    {
      "fingerprint": "sha256:9e2af70c31bb48d65a11e9c47f0add42c4118add370f6eb925e24bf09133ac7a",
      "revoked_at": "2026-03-15T14:22:00Z",
      "reason": "key_compromise"
    },
    {
      "fingerprint": "sha256:c4118add370f6eb925e24bf09133ac7a9e2af70c31bb48d65a11e9c47f0add42",
      "revoked_at": "2026-04-01T11:00:00Z",
      "reason": "superseded"
    }
  ]
}
```

### Revocation reasons

| Reason | When to use |
|--------|-------------|
| `key_compromise` | Private key leaked, stolen, or otherwise exposed. Treat any artifact signed with this key as suspect. |
| `superseded` | A new key has replaced this one on a planned schedule. The old artifacts may still be authentic. |
| `cessation_of_operation` | The signer is no longer in operation. No new signatures will be issued. |
| `privilege_withdrawn` | The signer is no longer authorized to sign for this domain (e.g., contractor offboarded). |

---

## Building and serving a revocation document

### Python

```python
from schemapin.revocation import (
    build_revocation_document,
    add_revoked_key,
    RevocationReason,
)
import json

doc = build_revocation_document("example.com")
add_revoked_key(
    doc,
    "sha256:9e2af70c31bb48d65a11e9c47f0add42c4118add370f6eb925e24bf09133ac7a",
    RevocationReason.KEY_COMPROMISE,
)

with open("schemapin-revocations.json", "w") as f:
    json.dump(doc.to_dict(), f, indent=2)
```

### JavaScript

```javascript
import { buildRevocationDocument, addRevokedKey, RevocationReason } from 'schemapin';
import { writeFileSync } from 'node:fs';

const doc = buildRevocationDocument('example.com');
addRevokedKey(
  doc,
  'sha256:9e2af70c31bb48d65a11e9c47f0add42c4118add370f6eb925e24bf09133ac7a',
  RevocationReason.KEY_COMPROMISE,
);
writeFileSync('schemapin-revocations.json', JSON.stringify(doc, null, 2));
```

### Go

```go
import (
    "encoding/json"
    "os"

    "github.com/ThirdKeyAi/schemapin/go/pkg/revocation"
)

doc := revocation.BuildRevocationDocument("example.com")
revocation.AddRevokedKey(
    doc,
    "sha256:9e2af70c31bb48d65a11e9c47f0add42c4118add370f6eb925e24bf09133ac7a",
    revocation.ReasonKeyCompromise,
)

data, _ := json.MarshalIndent(doc, "", "  ")
os.WriteFile("schemapin-revocations.json", data, 0644)
```

### Rust

```rust
use schemapin::revocation::{add_revoked_key, build_revocation_document};
use schemapin::types::revocation::RevocationReason;

let mut doc = build_revocation_document("example.com");
add_revoked_key(
    &mut doc,
    "sha256:9e2af70c31bb48d65a11e9c47f0add42c4118add370f6eb925e24bf09133ac7a",
    RevocationReason::KeyCompromise,
);

std::fs::write(
    "schemapin-revocations.json",
    serde_json::to_string_pretty(&doc)?,
)?;
```

### Hosting

Serve the JSON from the same server that hosts `.well-known/schemapin.json`. Cache aggressively but with a short max-age — see [Deployment guide](deployment.md#cache-control) for recommended `Cache-Control` headers (5 minutes is the conventional value: long enough to absorb traffic spikes, short enough that revocations propagate quickly).

---

## Checking revocation as a verifier

You usually don't call revocation primitives directly — `verify_schema_offline` / `verify_schema_with_resolver` and their skill counterparts do it for you. But the helpers are public for direct inspection:

### Python

```python
from schemapin.revocation import (
    check_revocation,            # standalone document
    check_revocation_combined,   # inline list + standalone document
    fetch_revocation_document,   # HTTP fetch helper
)

# Direct check against a single document
try:
    check_revocation(rev_doc, fingerprint)
except KeyRevokedError as e:
    print(f"key revoked: {e.reason}")

# Combined check (use this in production)
try:
    check_revocation_combined(
        revoked_keys_list=discovery.revoked_keys,
        revocation_doc=rev_doc,
        fingerprint=fingerprint,
    )
except KeyRevokedError as e:
    handle_revocation(e)
```

### Rust

```rust
use schemapin::revocation::check_revocation_combined;
use schemapin::error::Error;

match check_revocation_combined(
    &discovery.revoked_keys,
    revocation_doc.as_ref(),
    &fingerprint,
) {
    Ok(()) => { /* not revoked */ }
    Err(Error::Verification { code, message }) if code == ErrorCode::KeyRevoked => {
        // revoked — fail the verification
    }
    Err(other) => return Err(other),
}
```

The verification flow inside `verify_schema_offline` checks both mechanisms together, in this order:

1. The fingerprint matches an entry in `discovery.revoked_keys` → `KEY_REVOKED`.
2. The fingerprint matches a `revoked_keys[].fingerprint` in the standalone document → `KEY_REVOKED`.
3. Otherwise, continue to TOFU pinning.

A revoked key never reaches the signature-verify step — it fails closed before any cryptographic work happens.

---

## Combined revocation checking

Discovery documents *may* carry both `revoked_keys` (inline) and a `revocation_endpoint` (pointing at a standalone document). Verifiers MUST honour both. The helpers above (`check_revocation_combined` in every language) handle the union semantics: a fingerprint is revoked if it appears in **either** list.

This is also why trust bundles bake in both: an offline bundle stores the inline list with the discovery and fetches the standalone document at bundle-build time so the offline verifier sees the same revocation set as an online one.

---

## Operational playbook

When a key is compromised:

1. **Generate the new key** with `KeyManager.generate_keypair()` (or your language's equivalent) and store the private key in your secret manager. Do not reuse the old key id.
2. **Sign your active schemas** with the new key. Distribute the new signatures.
3. **Update `.well-known/schemapin.json`**:
   - Replace `public_key_pem` with the new public key.
   - Add the old fingerprint to `revoked_keys` (or add it to your standalone revocation document, ideally both for belt-and-suspenders).
4. **Bust caches**. Most CDNs honour a `Cache-Control: max-age=300` on the discovery doc; if you need faster propagation, purge the cache directly.
5. **Notify pinners**. Anyone who has TOFU-pinned the old key will hit a `KEY_REVOKED` error on the next verify and need to re-pin. Communicate the rotation through your usual channels (changelog, status page, security advisory).
6. **Rebuild trust bundles** if you publish them — see [Trust bundles](trust-bundles.md#bundle-freshness).

When a key is retired (planned rotation, no compromise):

- Same steps, but use `RevocationReason.SUPERSEDED`. Existing artifacts signed with the old key remain authentic; only new signatures should use the new key. Plan a deprecation window before removing the old key from `revoked_keys` (some pinners may take a while to roll forward).

---

## Common mistakes

- **Forgetting the `sha256:` prefix.** Fingerprints in revocation lists must include it. Plain hex is rejected.
- **Hosting the revocation doc on a different origin.** Most clients fetch with the same TLS posture as discovery; cross-origin fetches can fail silently. Co-locate.
- **Only revoking inline.** If you have a `revocation_endpoint` published, verifiers will fetch it. Make sure the standalone document is also up to date or remove the field.
- **Forgetting case sensitivity.** Fingerprints are lowercase hex. SHA-256 helpers in some languages emit uppercase by default — normalise before storing.

---

## See also

- [Trust bundles](trust-bundles.md) — package discovery + revocation for offline verification
- [Deployment](deployment.md) — serving `.well-known/schemapin-revocations.json` in production
- [API reference](api-reference.md#revocation) — full revocation API surface in every language
- [Technical specification — Section 8](https://github.com/ThirdKeyAI/SchemaPin/blob/main/TECHNICAL_SPECIFICATION.md#8-key-revocation) — the normative wire format
