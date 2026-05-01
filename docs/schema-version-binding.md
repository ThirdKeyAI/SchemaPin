# Schema Version Binding (`schema_version` + `previous_hash`)

> **Status:** v1.4.0-alpha.2 — implemented in **Rust, Python, JavaScript, and Go**. All four implementations produce byte-identical wire format.

A v1.3 signature pins a key to a tool, but a developer publishing a *new version* of the same tool has no way to declare it as such. Clients with the prior schema pinned can't tell whether the new bytes are an authorized v2.1.0 succeeding the v2.0.0 they trust, or an unauthorized substitution under the same name. ECDSA signatures alone don't help — both versions are validly signed by the same key.

SchemaPin v1.4 adds two OPTIONAL fields to `.schemapin.sig` (and to schema signatures) that, together, give publishers a way to declare lineage and verifiers a way to enforce it:

- **`schema_version`** — caller-supplied semver string identifying *this* version of the artifact. Opaque to SchemaPin (treated as a tag).
- **`previous_hash`** — `sha256:<hex>` of the prior signed version's `skill_hash`. Forms a hash chain across successive signatures.

The fields are surfaced on `VerificationResult` for inspection but are **not automatically enforced** — callers opt into chain verification by calling `verify_chain` (or the language equivalent) with both the current and previous signature documents.

---

## Wire format

```json
{
  "schemapin_version": "1.4",
  "skill_name": "example-skill",
  "skill_hash": "sha256:b7e8f9...",
  "signature": "MEUCIQ...",
  "signed_at": "2026-04-30T12:00:00Z",
  "expires_at": "2026-10-30T12:00:00Z",
  "schema_version": "2.1.0",
  "previous_hash": "sha256:a1b2c3...",
  "domain": "thirdkey.ai",
  "signer_kid": "thirdkey-2026-04",
  "file_manifest": { /* ... */ }
}
```

Either field, when present, bumps `schemapin_version` to `"1.4"`. Documents without either field remain `"1.3"`. v1.3 verifiers ignore the new fields entirely.

See [Technical specification §18](https://github.com/ThirdKeyAI/SchemaPin/blob/main/TECHNICAL_SPECIFICATION.md#18-schema-version-binding-v14) for the normative definition.

---

## Signing with lineage

### Rust

```rust
use schemapin::skill::{sign_skill_with_options, SignOptions};

// Initial release
let v1 = sign_skill_with_options(
    &dir_v1,
    &priv_pem,
    "example.com",
    SignOptions::new().with_schema_version("1.0.0"),
)?;
// v1.skill_hash → "sha256:a1b2c3..."

// Next release: chain to v1
let v2 = sign_skill_with_options(
    &dir_v2,
    &priv_pem,
    "example.com",
    SignOptions::new()
        .with_schema_version("1.1.0")
        .with_previous_hash(&v1.skill_hash),
)?;
```

### Python

```python
from schemapin.skill import SkillSigner, SignOptions

v1 = SkillSigner.sign_with_options(
    dir_v1, priv_pem, "example.com",
    SignOptions(schema_version="1.0.0"),
)

v2 = SkillSigner.sign_with_options(
    dir_v2, priv_pem, "example.com",
    SignOptions(
        schema_version="1.1.0",
        previous_hash=v1["skill_hash"],
    ),
)
```

### JavaScript

```javascript
import { signSkillWithOptions } from 'schemapin';

const v1 = signSkillWithOptions(dirV1, privPem, 'example.com', {
  schemaVersion: '1.0.0',
});

const v2 = signSkillWithOptions(dirV2, privPem, 'example.com', {
  schemaVersion: '1.1.0',
  previousHash: v1.skill_hash,
});
```

### Go

```go
import "github.com/ThirdKeyAi/schemapin/go/pkg/skill"

v1, _ := skill.SignSkillWithOptions(dirV1, privPEM, "example.com", skill.SignOptions{
    SchemaVersion: "1.0.0",
})

v2, _ := skill.SignSkillWithOptions(dirV2, privPEM, "example.com", skill.SignOptions{
    SchemaVersion: "1.1.0",
    PreviousHash:  v1.SkillHash,
})
```

---

## Verifying lineage

`verify_skill_offline` (and the per-language equivalents) automatically copy `schema_version` and `previous_hash` onto the result for inspection — no enforcement.

To **enforce** that a new signature legitimately succeeds a known-good previous one, call `verify_chain` (or the language equivalent) explicitly. Both signatures must already have been cryptographically verified independently — the chain check is pure metadata; it doesn't re-evaluate any signatures.

### Rust

```rust
use schemapin::skill::{verify_chain, ChainError};

// First, verify v2 cryptographically:
let v2_result = verify_skill_offline(&dir_v2, &discovery, None, None, None, Some("tool"));
assert!(v2_result.valid);

// Then enforce the chain against the trusted predecessor:
match verify_chain(&v2_sig, &v1_sig) {
    Ok(()) => { /* roll forward */ }
    Err(ChainError::NoPreviousHash) => {
        // v2 doesn't claim a predecessor. Treat as suspicious for
        // tools that previously had a chain.
    }
    Err(ChainError::Mismatch { expected, got }) => {
        // v2 claims a different predecessor than the one we trust.
        // Likely an unauthorized substitution.
    }
}
```

### Python

```python
from schemapin.skill import verify_chain, ChainError

try:
    verify_chain(v2_sig, v1_sig)
except ChainError as e:
    # ChainError is a subclass of ValueError; message includes the mismatch
    log.warning("chain failed: %s", e)
```

### JavaScript

```javascript
import { verifyChain, ChainError } from 'schemapin';

try {
    verifyChain(v2Sig, v1Sig);
} catch (err) {
    if (err instanceof ChainError) {
        // err.kind is 'no_previous_hash' or 'mismatch'
    } else {
        throw err;
    }
}
```

### Go

```go
import (
    "errors"
    "github.com/ThirdKeyAi/schemapin/go/pkg/skill"
)

if err := skill.VerifyChain(v2Sig, v1Sig); err != nil {
    var ce *skill.ChainError
    if errors.As(err, &ce) {
        switch ce.Kind {
        case skill.ChainErrorNoPreviousHash:
            // ...
        case skill.ChainErrorMismatch:
            // ce.Expected, ce.Got
        }
    }
}
```

---

## Operational pattern

A publisher rolling a chain SHOULD:

1. After signing v_n, record the resulting `skill_hash` in their build pipeline.
2. When signing v_{n+1}, set `previous_hash = skill_hash_of_v_n`.
3. Distribute v_{n+1} so verifiers can resolve v_n (e.g., publish both, or include v_n's hash in a registry).

A verifier enforcing the chain SHOULD maintain a per-tool `latest_known_hash` next to the TOFU public-key pin. On encountering a new signature with `previous_hash`:

| State | Action |
|-------|--------|
| matches `latest_known_hash` | accept, roll forward |
| empty | depends on policy: prompt, accept-with-warning, or reject for tools that previously chained |
| present but mismatch | likely unauthorized substitution — fail or prompt the operator |

This pairs cleanly with `schema_version`: enforce monotonic version progression as a separate policy layer (e.g., refuse downgrades).

---

## Why this defends against rug pulls

A rug pull is an unauthorized substitution of a tool's behavior under the same identity. Without lineage:

- Attacker compromises the publisher's signing key (or the publisher acts in bad faith).
- Attacker re-signs a tampered schema with the same `signer_kid`. The TOFU pin still matches.
- Verifier accepts the new schema as authentic. Behavior changes silently.

With lineage, the rug-pull either:

- **Omits `previous_hash`** — discoverable: a verifier that previously saw chained signatures can fail or prompt on the missing field.
- **Lies about `previous_hash`** — verifier compares against its `latest_known_hash` and catches the mismatch.

Lineage doesn't prevent compromise of the signing key — but it gives operators a chance to *notice* a substitution rather than silently load it.

---

## Backward compatibility

| Verifier ↓ / Signer → | v1.3 sig | v1.4 sig (no lineage) | v1.4 sig (with lineage) |
|-----------------------|----------|------------------------|--------------------------|
| **v1.3 verifier** | works | works (fields ignored) | works (fields ignored) |
| **v1.4 verifier** | works (no lineage) | works (no lineage) | lineage surfaced; chain enforcement opt-in |

Both directions are intentional — v1.4 is purely additive. There is no situation where bumping a verifier or a signer to v1.4 breaks an existing deployment.

---

## See also

- [Technical specification §18](https://github.com/ThirdKeyAI/SchemaPin/blob/main/TECHNICAL_SPECIFICATION.md#18-schema-version-binding-v14)
- [Signature expiration](signature-expiration.md) — the other v1.4-alpha.1 feature
- [DNS TXT cross-verification](dns-txt.md) — second-channel anti-substitution defense, complementary to lineage
- [Revocation](revocation.md) — what to do *after* you discover a substitution
