# Signature Expiration (`expires_at`)

> **Status:** v1.4 — implemented in **Rust, Python, JavaScript, and Go**. `expires_at` is covered by the skill signature (signed-document format, `schemapin_version: "1.4"`) and verification is **fail-closed** past the expiry.

A v1.3 signature is valid forever once issued. There's a `signed_at` timestamp on every `.schemapin.sig`, but no expiration — a signature minted two years ago on an abandoned tool reads as "valid" identically to one minted yesterday. There's no forcing function for developers to re-sign after a security review, and verifiers can't distinguish *actively maintained* from *signed once and forgotten*.

SchemaPin v1.4 adds an OPTIONAL `expires_at` field to `.schemapin.sig`. Past the expiration (plus a 5-minute clock-skew allowance) verifiers **fail** with `SIGNATURE_EXPIRED`. A host that prefers the older "degraded, not failed" posture can opt in per call with `allow_expired`; then `valid` stays `true`, `expired` is set and a `signature_expired` warning is appended for policy gating. The field is part of the signed document, so it cannot be stripped or altered without invalidating the signature.

This page shows the Rust API; the other languages expose the same options (`allow_expired` in Python, `allowExpired` in JavaScript, `VerifyOptions.AllowExpired` in Go).

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

## Verifier semantics: fail-closed, with an explicit opt-out

`verify_skill_offline` applies the expiration check after a successful signature verification. The `VerificationResult` carries:

| Field | Type | Meaning |
|-------|------|---------|
| `valid` | `bool` | `false` when expired (default) or when `expires_at` is not strict RFC 3339 |
| `error_code` | `Option<ErrorCode>` | `SignatureExpired` for both cases |
| `expired` | `bool` | `true` if `expires_at` is set and now > expires_at + 300 s |
| `expires_at` | `Option<String>` | Mirrors the value from the signature when present |
| `warnings` | `Vec<String>` | `"signature_expired"` / `"signature_expires_at_unparseable"` only when `allow_expired` was used |

```rust
use schemapin::skill::{verify_skill_offline_with_options, VerifyOptions};

let result = verify_skill_offline_with_options(
    &skill_dir, &discovery, None, revocation.as_ref(), Some(&mut pin_store),
    &VerifyOptions { domain: Some("example.com"), tool_id: Some("payments-tool"), allow_expired: false },
);

if !result.valid {
    // SignatureExpired is a hard failure by default.
    return Err(format!("{:?}: {}", result.error_code, result.error_message.unwrap_or_default()).into());
}
```

### Opting in to degraded verification

```rust
let degraded = verify_skill_offline_with_options(
    &skill_dir, &discovery, None, None, None,
    &VerifyOptions { allow_expired: true, ..VerifyOptions::default() },
);
if degraded.valid && degraded.expired {
    log::warn!("skill signature expired at {} — policy decision", degraded.expires_at.as_deref().unwrap_or("?"));
}
```

### Why fail closed?

The original alpha design degraded instead of failing, by analogy with the TLS deployment cliff. In practice no consumer checked `expired`, so an expired signature was indistinguishable from a fresh one — and because the field was not signed it could simply be removed. Failing closed makes the expiry a real security property; the deployment-cliff concern belongs to the policy layer, which is why `allow_expired` exists as a deliberate, per-call choice rather than the default.

### Unparseable timestamps

`expires_at` must be strict RFC 3339 (`2026-10-30T12:00:00Z` or with a numeric offset). A value that does not parse is treated like an expired signature (`SIGNATURE_EXPIRED`): a malformed expiry is indistinguishable from a stripped one. With `allow_expired` it degrades to a `signature_expires_at_unparseable` warning instead.

---

## Confidence scoring

Together with the existing `signed_at`, `expires_at` enables a simple confidence model:

| Signal | Confidence |
|--------|------------|
| `signed_at` recent (< 30 days), `expires_at` distant | high |
| `signed_at` old, `expires_at` distant | medium |
| `expires_at` near (< 7 days) | medium-low |
| `expired = true` (only reachable with `allow_expired`) | degraded — gate on policy |
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
| **v1.4 verifier** | works (no expiration applied) | works; fails with `SIGNATURE_EXPIRED` past `expires_at` |

Both directions are intentional — v1.4 is purely additive. There is no situation where bumping a verifier or a signer to v1.4 breaks an existing deployment.

---

## See also

- [Technical specification — Section 16](https://github.com/ThirdKeyAI/SchemaPin/blob/main/TECHNICAL_SPECIFICATION.md#16-signature-expiration-v14) — normative wire format
- [DNS TXT cross-verification](dns-txt.md) — the other v1.4 feature, also additive
- [Skill signing](skill-signing.md) — the v1.3 base this builds on
- [Revocation](revocation.md) — orthogonal: both are hard failures by default
