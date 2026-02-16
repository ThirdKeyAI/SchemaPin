# SchemaPin Roadmap

![Version](https://img.shields.io/badge/current-v1.3.0-brightgreen)
![Next](https://img.shields.io/badge/next-v1.4.0_(planning)-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**Cryptographic schema integrity verification for AI tool ecosystems — the trust anchor of the ThirdKey trust stack.**

---

## Release Timeline

| Version | Target | Headline | Status |
|---------|--------|----------|--------|
| **1.0.0** | 2026-01 | Core verification, TOFU pinning, 4-language support | Shipped |
| **1.1.0** | 2026-01 | Revocation documents, standalone revocation endpoint | Shipped |
| **1.2.0** | 2026-02 | Offline verification, trust bundles, resolver abstraction | Shipped |
| **1.3.0** | 2026-02 | AgentSkills security — skill folder signing | **Shipped** |
| **1.4.0** | Q2-Q3 2026 | Signature lifecycle, version binding, A2A trust | Planning |
| **1.5.0** | Q4 2026 | Multi-key endorsement, permissions, advanced revocation | Planning |

---

## v1.2.0 — Shipped

Offline verification for air-gapped environments, trust bundles for pre-distributing verified schemas, and `VerificationResolver` trait for pluggable resolution strategies. All four language implementations (Rust, JavaScript, Python, Go) updated.

See release notes for full details.

---

## v1.3.0 — AgentSkills Security: Skill Signing (Q1 2026)

The AgentSkills specification (SKILL.md) has become the universal format for AI coding agent skills across Claude Code, Codex, Cursor, Copilot, and OpenClaw — but ships with zero cryptographic security. The ClawHavoc attack (January 2026, 341 malicious skills on ClawHub delivering AMOS infostealer) demonstrated the urgent need for a trust layer.

SchemaPin v1.3.0 extends the existing ECDSA P-256 signing infrastructure to sign and verify file-based skill folders. Same keys, same `.well-known` discovery, new target format.

### SkillSigner Module

New module alongside existing schema signing. The cryptographic primitives are identical — what changes is the canonicalization target: a folder of files instead of a JSON object.

| Item | Details |
|------|---------|
| `SkillSigner` class/struct | Sign and verify AgentSkills-compatible skill folders |
| Merkle tree canonicalization | Walk directory in sorted order → SHA-256 per file (`relative_path + file_bytes`) → SHA-256 root hash of concatenated per-file hashes |
| `.schemapin.sig` file format | Signature file placed alongside SKILL.md with `schemapin_version`, `skill_hash`, `signature`, `domain`, `signer_kid`, `file_manifest` |
| Per-file tamper detection | The file manifest enables reporting which specific file was modified |

### `.schemapin.sig` Format

```json
{
  "schemapin_version": "1.3",
  "skill_name": "example-skill",
  "skill_hash": "sha256:a1b2c3d4e5...",
  "signature": "MEUCIQD...",
  "signed_at": "2026-02-14T12:00:00Z",
  "domain": "thirdkey.ai",
  "signer_kid": "thirdkey-2026-01",
  "file_manifest": {
    "SKILL.md": "sha256:d4e5f6...",
    "scripts/setup.sh": "sha256:g7h8i9...",
    "references/api-docs.md": "sha256:j0k1l2..."
  }
}
```

### CLI Extensions

| Command | Description |
|---------|-------------|
| `schemapin-sign --skill ./skill-dir/ --key private.pem --domain thirdkey.ai` | Sign a skill folder |
| `schemapin-verify --skill ./skill-dir/ --domain thirdkey.ai` | Verify a skill folder |
| `schemapin-verify --skill ./skill-dir/ --domain thirdkey.ai --auto-pin` | Verify with TOFU auto-pin |

### Cross-Language Support

All four language implementations receive matching SkillSigner implementations:

| Language | Priority | Status | Notes |
|----------|----------|--------|-------|
| Python | First (fastest iteration, most skill authors) | **Shipped** | `schemapin/skill.py` — `SkillSigner` class |
| Rust | Second (blocks Symbiont runtime integration) | **Shipped** | `src/skill.rs` — module-level functions, 22 tests |
| JavaScript | Third (Node.js ecosystem, ClawHub tooling) | **Shipped** | `src/skill.js` — module-level functions, 22 tests |
| Go | Fourth (CLI distribution) | **Shipped** | `pkg/skill/skill.go` — package-level functions, 22+ tests |

Cross-language interop tests ensure a Python-signed skill verifies in Rust/JS/Go.

### What Does NOT Change

The existing `.well-known/schemapin.json` discovery, TOFU key pinning database, revocation endpoints, key rotation, and tool schema signing are all unaffected. Skill signing is purely additive.

---

## v1.4.0 — Signature Lifecycle, Version Binding & A2A Trust (Q2-Q3 2026)

All v1.4 additions are optional fields — fully backward compatible with v1.3 clients.

### Signature Expiration / TTL

Right now, a signature is valid forever once created. There's a `signed_at` timestamp but no `expires_at`. A signature from 2 years ago on an abandoned tool is just as "valid" as one from yesterday — there's no forcing function for developers to re-sign after security reviews, and clients can't distinguish "actively maintained" from "signed once and forgotten."

| Item | Details |
|------|---------|
| `expires_at` field | Optional ISO 8601 timestamp in both schema signatures and `.schemapin.sig` |
| Degraded vs. failed | Expired signatures are treated as degraded (lower confidence), not hard failures — avoids breaking tools when a dev misses a renewal |
| Confidence scoring | Pairs with a confidence model: recently signed > old but valid > expired > unsigned |

**Format addition to `.schemapin.sig`:**

```json
{
  "signed_at": "2026-02-14T12:00:00Z",
  "expires_at": "2026-08-14T12:00:00Z"
}
```

### Schema Version Binding

SchemaPin signs a schema at a point in time, but there's no concept of "this is version 3.2 of this tool's schema, superseding version 3.1." If a developer legitimately updates their tool, clients with the old schema pinned have no way to know whether the new schema is an authorized upgrade or a rug pull.

| Item | Details |
|------|---------|
| `schema_version` field | Optional version string in signature metadata |
| `previous_hash` field | SHA-256 hash of the prior signed version, creating a hash chain |
| Lineage verification | Clients verify that a schema update is part of an authorized chain rather than an out-of-band substitution |

No new crypto required — just metadata. The hash chain is lightweight and elegant.

### DNS TXT Cross-Verification

AgentPin already uses `_agentpin.{domain}` TXT records, but SchemaPin doesn't leverage DNS yet. Adding a `_schemapin.{domain}` TXT record containing the key fingerprint gives multi-channel verification without requiring a GitHub repo. DNS is controlled through a completely different credential chain than HTTPS hosting, so compromising one doesn't compromise the other.

| Item | Details |
|------|---------|
| `_schemapin.{domain}` TXT record | Contains key fingerprint (JWK thumbprint) |
| Cross-check | Clients verify that the key from `.well-known` matches what DNS says |
| Optional | Enhances confidence when present, does not block verification when absent |

**Example TXT record:**

```
_schemapin.example.com. IN TXT "v=schemapin1; kid=acme-2026-01; fp=sha256:a1b2c3d4..."
```

### Canonicalization Algorithm Identifier

The current spec hardcodes the canonicalization algorithm (sorted keys, no whitespace, UTF-8). If the algorithm ever needs to change (and JSON canonicalization is notoriously tricky across languages), there's no way to signal which algorithm was used.

| Item | Details |
|------|---------|
| `canonicalization` field | Algorithm identifier in signature metadata, e.g. `"schemapin-v1"` |
| Forward compatibility | New algorithms can be introduced without breaking existing signatures |

Trivial to add now, saves a painful migration later.

### A2A Context for Schema Verification

When agents collaborate via A2A (Agent-to-Agent), tool schemas cross trust boundaries. SchemaPin v1.4.0 ensures that tool integrity verification extends seamlessly into A2A networks — every tool invoked through an A2A bridge is verified against its provider's signed schema.

| Item | Details |
|------|---------|
| `A2aVerificationContext` | New type wrapping `VerificationResult` with A2A caller identity, delegation depth, originating domain |
| `verify_schema_for_a2a()` | Extends `verify_schema_offline()` with A2A context validation |
| Domain scoping | Accept optional trusted domains list (from AgentPin `allowed_domains` constraints) |
| Intersection check | Scope verification to intersection of caller's allowed domains and tool provider's domain |

### Trust Bundle Distribution for A2A Networks

| Item | Details |
|------|---------|
| Bundle signing | Sign trust bundles with a bundle authority key |
| `merge_trust_bundles()` | Combine bundles from multiple sources with deduplication (newest wins) |
| TOFU for bundles | TOFU pinning for bundle authority keys |
| JSON-RPC method | `schemapin/trustBundle` for A2A bundle exchange |

### Cross-Agent Tool Schema Caching

| Item | Details |
|------|---------|
| Cache key | `(tool_id, domain, schema_hash)` triple |
| Storage | In-memory with configurable TTL and max entries |
| Shared cache | Optional shared cache across agents in same runtime |

### Cross-Language Support

All four language implementations (Rust, JavaScript, Python, Go) receive matching implementations of all v1.4 features.

---

## v1.5.0 — Multi-Key Endorsement, Permissions & Advanced Revocation (Q4 2026)

### Multi-Key / Organizational Endorsement

The `.well-known/schemapin.json` should support an array of public keys with roles rather than a single `public_key_pem`. This is the enterprise compliance differentiator — organizations can enforce policies like "require both a developer and a reviewer signature."

**Discovery document format:**

```json
{
  "schema_version": "1.5",
  "developer_name": "Acme Corp",
  "public_keys": [
    {
      "kid": "acme-dev-2026-01",
      "public_key_pem": "...",
      "role": "developer",
      "name": "Alice (Engineering)"
    },
    {
      "kid": "acme-security-2026-01",
      "public_key_pem": "...",
      "role": "reviewer",
      "name": "Security Team"
    }
  ]
}
```

| Item | Details |
|------|---------|
| `public_keys` array | Replaces single `public_key_pem` (single-key remains valid as shorthand) |
| Key roles | `developer`, `reviewer`, `auditor` — extensible |
| `signatures` array in `.schemapin.sig` | Replaces single `signature` field for countersigning |
| Policy enforcement | Clients can require signatures from specific roles |

Sequential countersigning approach — minimal protocol disruption, maximum enterprise value.

### Scope / Permission Declarations

SchemaPin verifies that a schema hasn't been *tampered with*, but says nothing about what the schema *claims to do*. A signed schema that says "I need filesystem access, network access, and the ability to execute arbitrary commands" is cryptographically valid but potentially terrifying.

| Item | Details |
|------|---------|
| `declared_permissions` field | Optional array in signature metadata enumerating claimed capabilities |
| Attestation record | Auditable record of what the developer attested their tool requires at signing time |
| Tamper detection | If the schema later changes to request more permissions without a new signature, verification fails |
| Policy bridge | Doesn't enforce at SchemaPin layer (that's Symbiont's job), but feeds into policy enforcement |

This bridges SchemaPin into the Symbiont policy enforcement story naturally.

### Source Repository Verification

Cross-reference signed schemas against their source repository to boost verification confidence.

| Item | Details |
|------|---------|
| `source_repo` field | Optional repository URL in signature metadata |
| Commit binding | Optional `source_commit` hash linking signature to a specific commit |
| Confidence boost | Verification that the signed artifact matches what's in the public repo |

### Advanced Revocation & Key Lifecycle

| Item | Details |
|------|---------|
| CRL distribution | Certificate Revocation List distribution for offline environments |
| Key rotation ceremonies | Structured key rotation with grace periods and automatic re-signing |
| Revocation push notifications | Real-time revocation alerts to subscribed agents |
| OCSP-style checking | Online status checking for time-sensitive verification |

---

## Beyond (Unscheduled)

| Feature | Description |
|---------|-------------|
| Verification Telemetry | Optional `reporting_endpoint` in `.well-known/schemapin.json` for anonymized verification reports (tool_id, success/failure, error_code, timestamp). Opt-in on both sides. Feeds into transparency log. |
| Hardware-Backed Signing | HSM and TPM support for schema signing keys |
| Federated Trust Registries | Shared registries for cross-organization schema trust |
| Transparency Log | Append-only log of all schema signatures for auditability |

---

## Priority Stack

Sequenced for maximum impact with minimum effort. All items are backward compatible — every one is an optional field addition. Existing v1.3 clients ignore what they don't understand.

| Priority | Feature | Target | Effort | Impact |
|----------|---------|--------|--------|--------|
| 1 | Signature expiration | v1.4 | Small | Closes the "stale signature" gap every enterprise buyer will ask about |
| 2 | Multi-key endorsement | v1.5 | Medium | The enterprise compliance differentiator |
| 3 | DNS TXT cross-verification | v1.4 | Small | Strongest anti-compromise signal for lowest cost |
| 4 | Schema version binding | v1.4 | Small | Hash chain prevents upgrade-path attacks |
| 5 | Source repo verification | v1.5 | Medium | Strong confidence boost via cross-referencing |
| 6 | Declared permissions | v1.5 | Small | Bridges into Symbiont policy story |
| 7 | Canonicalization identifier | v1.4 | Trivial | Future-proofing while it's free |
| 8 | Reporting endpoint | Beyond | Medium | Important but requires ecosystem scale |

---

## Contributing

We welcome input on roadmap priorities:

- **GitHub Discussions** — Open a discussion in the [SchemaPin repository](https://github.com/ThirdKeyAI/SchemaPin/discussions)
- **Contributing Guide** — See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup
- **Security** — For security-sensitive feedback, see SECURITY.md

---

*Last updated: 2026-02-15*
