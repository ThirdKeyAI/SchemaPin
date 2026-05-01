# Signature Expiration (`expires_at`)

> **Status:** v1.4.0-alpha.1 — **Rust only.** Python, JavaScript, and Go ports follow in subsequent alphas before the v1.4.0 release. The wire format is frozen; only the implementations need to catch up.

A v1.3 signature is valid forever once issued. There's a `signed_at` timestamp on every `.schemapin.sig`, but no expiration — a signature minted two years ago on an abandoned tool reads as "valid" identically to one minted yesterday. There's no forcing function for developers to re-sign after a security review, and verifiers can't distinguish *actively maintained* from *signed once and forgotten*.

SchemaPin v1.4 adds an OPTIONAL `expires_at` field to `.schemapin.sig`. Past the expiration, verifiers **degrade** the result (warning, lower confidence) — they don't fail it. Cryptographically the signature is still intact, so callers retain the ability to inspect signed metadata. What changes is the trust posture: an expired signature feeds policy gating and confidence scoring, not a hard refusal.

This page covers the Rust API. The other languages follow the same wire format.

---

## Wire format

`.schemapin.sig` documents written with an expiration carry an ISO 8601 / RFC 3339 timestamp in the new `expires_at` field, and bump `schemapin_version` to `"1.4"`:

```json
{
  "schemapin_version": "1.4",
  "skill_name": "example-skill",
  "skill_hash": "sha256:a1b2c3...",
  "signature": "MEUCIQ...",
  "signed_at": "2026-04-30T12:00:00Z",
  "expires_at": "2026-10-30T12:00:00Z",
  "domain": "thirdkey.ai",
  "signer_kid": "thirdkey-2026-04",
  "file_manifest": { /* ... */ }
}
```

Documents written WITHOUT `expires_at` continue to advertise `schemapin_version: "1.3"` — full backward compatibility. v1.3 verifiers ignore the field if they encounter it; v1.4 verifiers handle both.

---

## Signing with a TTL

The legacy `sign_skill(...)` is preserved for v1.3 callers. To opt into expiration, use the v1.4 `SignOptions` builder + `sign_skill_with_options`:

```rust
use schemapin::skill::{sign_skill_with_options, SignOptions};
use chrono::Duration;

// 180-day TTL
let opts = SignOptions::new().with_expires_in(Duration::days(180));
let sig = sign_skill_with_options(
    &skill_dir,
    &private_key_pem,
    "example.com",
    opts,
)?;

assert!(sig.expires_at.is_some());
assert_eq!(sig.schemapin_version, "1.4");
```

`SignOptions` is also where future v1.4 sign-time options will land (scan-aware fields, schema_version, etc.):

```rust
let opts = SignOptions::new()
    .with_signer_kid("acme-2026-04")
    .with_skill_name("payments-tool")
    .with_expires_in(Duration::days(90));
```

---

## Verifier semantics: degraded, not failed

`verify_skill_offline` automatically applies the expiration check after a successful signature verification. The `VerificationResult` gains two new fields:

| Field | Type | Meaning |
|-------|------|---------|
| `valid` | `bool` | Cryptographic signature validity — **unchanged by expiration** |
| `expired` | `bool` | `true` if `expires_at` is set and now > expires_at |
| `expires_at` | `Option<String>` | Mirrors the value from the signature when present |
| `warnings` | `Vec<String>` | Includes `"signature_expired"` when expired |

```rust
use schemapin::skill::verify_skill_offline;

let result = verify_skill_offline(
    &skill_dir, &discovery, None, revocation.as_ref(),
    Some(&mut pin_store), Some("payments-tool"),
);

if !result.valid {
    return Err("signature invalid".into());
}

if result.expired {
    log::warn!(
        "skill signature expired at {} — treat as degraded trust",
        result.expires_at.as_deref().unwrap_or("(unknown)"),
    );
    // Policy decision: refuse, downgrade, prompt, or allow with caveat
}
```

### Why degrade instead of fail?

A hard fail would create a deployment cliff every time a maintainer misses a renewal — the same UX problem TLS certificate expiry causes. SchemaPin's design choice: surface the staleness, let the policy layer decide. A risk-averse runtime can refuse expired signatures; a permissive one can prompt; a CI pipeline can fail builds when expiration is within a configurable window.

The cryptographic guarantee (this artifact was signed by this key) is unchanged by elapsed time. What changes is the freshness signal that an actively-maintained publisher would re-sign periodically.

### Unparseable timestamps

If `expires_at` is present but cannot be parsed as RFC 3339, the verifier emits a `signature_expires_at_unparseable` warning and treats the signature as **not expired** — fail-open on parse, not fail-closed. Malformed metadata should not silently invalidate otherwise-valid signatures.

```rust
if result.warnings.iter().any(|w| w == "signature_expires_at_unparseable") {
    // Log; the publisher's tooling is producing malformed metadata.
}
```

---

## Confidence scoring

Together with the existing `signed_at`, `expires_at` enables a simple confidence model:

| Signal | Confidence |
|--------|------------|
| `signed_at` recent (< 30 days), `expires_at` distant | high |
| `signed_at` old, `expires_at` distant | medium |
| `expires_at` near (< 7 days) | medium-low |
| `expired = true` | degraded — gate on policy |
| no `expires_at` (v1.3) | unchanged — assume long-lived |

Implementations that need scoring can compute it from the result:

```rust
fn confidence(result: &VerificationResult) -> &'static str {
    if !result.valid { return "invalid"; }
    if result.expired { return "degraded"; }
    match result.expires_at.as_deref() {
        None => "stable",
        Some(ts) => {
            let exp = chrono::DateTime::parse_from_rfc3339(ts).ok();
            let near = exp.map(|t| {
                t.with_timezone(&chrono::Utc) - chrono::Utc::now()
                    < chrono::Duration::days(7)
            }).unwrap_or(false);
            if near { "expiring_soon" } else { "fresh" }
        }
    }
}
```

---

## Backward compatibility

| Verifier ↓ / Signature → | v1.3 sig (no `expires_at`) | v1.4 sig (with `expires_at`) |
|--------------------------|----------------------------|------------------------------|
| **v1.3 verifier** | works | works (field ignored) |
| **v1.4 verifier** | works (no expiration applied) | works (degrades when past `expires_at`) |

Both directions are intentional — v1.4 is purely additive. There is no situation where bumping a verifier or a signer to v1.4 breaks an existing deployment.

---

## See also

- [Technical specification — Section 16](https://github.com/ThirdKeyAI/SchemaPin/blob/main/TECHNICAL_SPECIFICATION.md#16-signature-expiration-v14) — normative wire format
- [DNS TXT cross-verification](dns-txt.md) — the other v1.4 feature, also additive
- [Skill signing](skill-signing.md) — the v1.3 base this builds on
- [Revocation](revocation.md) — orthogonal: revocation is hard-fail, expiration is degraded
