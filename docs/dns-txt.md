# DNS TXT Cross-Verification

> **Status:** v1.4.0-alpha.1 — **Rust only.** Python, JavaScript, and Go ports follow in subsequent alphas before the v1.4.0 release. The wire format is frozen; only the implementations need to catch up.

SchemaPin v1.3 anchors trust in HTTPS: a public key published at `https://example.com/.well-known/schemapin.json`, served over TLS, fingerprinted, and pinned. That works — but it leans on a single credential chain. An attacker with control of the TLS cert, the web origin, or the static-asset bucket can publish a forged discovery document and serve it as if it were the real one.

SchemaPin v1.4 adds an OPTIONAL second-channel verification: a DNS `TXT` record at `_schemapin.{domain}` whose contents include the same public-key fingerprint advertised by the discovery document. DNS is administered through a separate credential chain (registrar account, DNS provider, DNSSEC if deployed) — compromising one channel doesn't automatically compromise the other.

This page covers the Rust API. The other languages follow the same wire format.

---

## TXT record format

```
_schemapin.example.com.  3600  IN  TXT  "v=schemapin1; kid=acme-2026-04; fp=sha256:a1b2c3d4e5f6..."
```

Fields:

| Field | Required | Description |
|-------|----------|-------------|
| `v` | yes | Version tag, currently `schemapin1`. Unknown versions are rejected. |
| `fp` | yes | Key fingerprint as `sha256:<lowercase-hex>`. Must match SchemaPin's fingerprint format (SHA-256 of DER-encoded SubjectPublicKeyInfo). |
| `kid` | no | Optional key id. Useful for multi-key discovery documents (forward-compat with v1.5). |

**Whitespace** around `;` and `=` is tolerated. **Field order** is not significant. **Unknown fields** are ignored for forward compatibility — a v1.4 parser ignores fields a future v1.5 might add.

If multiple TXT records exist at `_schemapin.{domain}`, the parser selects the first one whose value contains `v=schemapin1`. Multiple TXT chunks within a single record are concatenated in emit order per RFC 1464.

---

## Verifier semantics

| State | Effect |
|-------|--------|
| **Absent** (no `_schemapin.{domain}` TXT record) | No effect — DNS TXT is purely additive |
| **Present and matching** (TXT `fp` equals SHA-256 of `discovery.public_key_pem`) | Verification succeeds; absence of mismatch is the trust signal |
| **Present and mismatching** | Hard failure with `DOMAIN_MISMATCH` error code |
| **Present and malformed** (missing `v` or `fp`, wrong `fp` format, unknown version) | Hard failure with `DISCOVERY_INVALID` |

The mismatch case is fail-closed because a publisher who *intentionally* published a TXT record has signaled that DNS is part of their trust chain. A divergence between DNS and `.well-known` indicates compromise of one of the two channels — and there's no way for the verifier to tell which is authentic. Better to refuse than to guess.

---

## Publishing the TXT record

The fingerprint is the SHA-256 of the DER-encoded SubjectPublicKeyInfo, formatted as `sha256:<hex>` — exactly the same fingerprint format SchemaPin uses everywhere else (revocation entries, key ids, TOFU pins).

Compute it from your published PEM:

```bash
# 1. Compute fingerprint
FP=$(openssl pkey -pubin -in pubkey.pem -outform DER \
  | openssl dgst -sha256 -hex \
  | awk '{print "sha256:" $2}')

# 2. Format the TXT record
echo "_schemapin.example.com. IN TXT \"v=schemapin1; kid=acme-2026-04; fp=$FP\""
```

Or programmatically:

```rust
use schemapin::crypto::calculate_key_id;

let fp = calculate_key_id(&public_key_pem)?;
let record = format!("v=schemapin1; kid=acme-2026-04; fp={}", fp);
```

Then publish via your DNS provider's standard TXT record interface. TTL of 3600 (1 hour) is conventional.

### Co-rotation with the discovery document

When you rotate a key, both the `.well-known/schemapin.json` `public_key_pem` AND the `_schemapin.{domain}` TXT record's `fp=` value must change. A divergence between the two — even a transient one during a rotation window — causes verifiers to fail closed on the `DOMAIN_MISMATCH` path. Coordinate the updates:

1. Update the DNS TXT record first; let it propagate (cache TTL).
2. Update `.well-known/schemapin.json` second.
3. Verifiers see the new fingerprint in both places, no mismatch fires.

For planned rotations, consider publishing the new record with a `kid=...` distinguishable from the old. v1.5 multi-key endorsement will let you list both keys for an overlap window.

---

## Verifying with DNS cross-check

The Rust API splits this into a parser/matcher (always available, no DNS deps) and an async fetcher (gated behind the `dns` Cargo feature):

### Cargo features

| Feature | Default | Brings in |
|---------|---------|-----------|
| `fetch` | off | `reqwest`, `tokio`, `async-trait` |
| `dns` *(NEW in v1.4)* | off | `hickory-resolver`, `tokio`, `async-trait` |

Enable the feature in your `Cargo.toml`:

```toml
[dependencies]
schemapin = { version = "1.4.0-alpha.1", features = ["dns"] }
```

### Parsing a TXT record

The parser is pure and always available — no DNS dependency:

```rust
use schemapin::dns::{parse_txt_record, DnsTxtRecord};

let txt: DnsTxtRecord = parse_txt_record(
    "v=schemapin1; kid=acme-2026-04; fp=sha256:a1b2c3..."
)?;

assert_eq!(txt.version, "schemapin1");
assert_eq!(txt.kid.as_deref(), Some("acme-2026-04"));
assert_eq!(txt.fingerprint, "sha256:a1b2c3...");
```

This is what you'd use if you were fetching TXT records yourself (some embedded environments) or if your DNS lookup is mediated by another layer.

### Cross-checking against discovery

Once you have a `DnsTxtRecord`, verify it matches the discovery document's key:

```rust
use schemapin::dns::verify_dns_match;

verify_dns_match(&discovery, &txt)?;  // Err on mismatch
```

A mismatch returns `Error::Verification { code: DomainMismatch, .. }`.

### Full skill verification with DNS

The high-level helper that ties it all together:

```rust
use schemapin::skill::verify_skill_offline_with_dns;

let result = verify_skill_offline_with_dns(
    &skill_dir,
    &discovery,
    /* signature_data */ None,
    revocation.as_ref(),
    Some(&mut pin_store),
    /* tool_id */ Some("payments-tool"),
    /* dns_txt */ Some(&txt),
);

if !result.valid {
    // Could be the regular signature/revocation/pin-mismatch failures,
    // OR a DOMAIN_MISMATCH if dns_txt didn't match the discovery key.
    return Err(result.error_message.unwrap_or_default().into());
}
```

When `dns_txt = None`, `verify_skill_offline_with_dns` behaves identically to `verify_skill_offline` — the cross-check is only applied when a record is provided. This lets callers fail closed on missing TXT (compute `dns_txt` from a successful lookup; treat `Ok(None)` as "no record published, proceed without cross-check") or fail closed on absent records by their own policy (treat `Ok(None)` as a verification failure at the caller layer).

### Async DNS fetch (with `dns` feature)

```rust
#[cfg(feature = "dns")]
use schemapin::dns::fetch_dns_txt;

let txt = fetch_dns_txt("example.com").await?;
//          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//          Ok(Some(record)) — record present and parseable
//          Ok(None)         — no _schemapin TXT record exists
//          Err(_)           — DNS resolution error or malformed record
```

The async fetcher uses `hickory-resolver` (the maintained successor to `trust-dns`). System resolver config is honoured by default; pass a custom config if you need to (e.g., DoH/DoT to avoid eavesdropping or recursive resolver poisoning).

---

## Lookup name construction

```
input "example.com"   → _schemapin.example.com
input "example.com."  → _schemapin.example.com   (trailing dot stripped)
```

Helper:

```rust
use schemapin::dns::txt_record_name;

assert_eq!(txt_record_name("example.com"),  "_schemapin.example.com");
assert_eq!(txt_record_name("example.com."), "_schemapin.example.com");
```

---

## Threat model

DNS TXT cross-verification is most valuable against:

- **HTTPS-origin compromise.** Attacker controls the web origin (compromised hosting account, expired domain not removed from CDN, ACME ownership-validation bypass) but does NOT control the registrar/DNS account. Without DNS cross-check, an attacker-published `.well-known/schemapin.json` would TOFU-pin and verify cleanly. With cross-check, the fingerprint mismatch fails closed.
- **TLS cert mis-issuance.** A rogue or coerced CA issues a cert for `example.com` to an attacker. Same defense — DNS is on a separate credential chain.
- **CDN cache-poisoning** for static `.well-known` assets — same shape as origin compromise.

It does NOT defend against:

- **Joint compromise of HTTPS origin + DNS.** If the attacker controls both, they can update both consistently.
- **Targeted DNS hijack at the verifier.** If the attacker can modify what a specific verifier resolves (rogue resolver, intercepted recursive query), they can fake a matching record. Use DNSSEC, DoH/DoT, or pinned recursive resolvers in high-stakes deployments.

DNS TXT is one defense in a layered posture: TOFU pinning + revocation documents + DNS cross-check + (eventually) v1.5 multi-key endorsement. None of them is sufficient alone.

---

## Backward compatibility

| Verifier ↓ / Publisher → | No TXT published | TXT published, matching | TXT published, mismatching |
|--------------------------|------------------|--------------------------|------------------------------|
| **v1.3 verifier** (no DNS check) | works | works | works (check absent) |
| **v1.4 verifier without `dns_txt`** | works | works | works (check skipped) |
| **v1.4 verifier with `dns_txt`** | n/a | works | **DOMAIN_MISMATCH** |

Publishing a TXT record never breaks v1.3 verifiers (they don't look). Verifying without `dns_txt` never breaks anything (the cross-check is opt-in). The fail-closed path only fires when both sides have opted in.

---

## See also

- [Technical specification — Section 17](https://github.com/ThirdKeyAI/SchemaPin/blob/main/TECHNICAL_SPECIFICATION.md#17-dns-txt-cross-verification-v14) — normative wire format
- [Signature expiration](signature-expiration.md) — the other v1.4 feature, also additive
- [Revocation](revocation.md) — what to do when a key (or your DNS account) is compromised
- AgentPin uses `_agentpin.{domain}` TXT records on the same pattern; the credential-separation argument is identical.
