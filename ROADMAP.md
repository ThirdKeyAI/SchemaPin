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
| **1.4.0** | Q2-Q3 2026 | Cross-agent tool trust for A2A networks | Planning |
| **1.5.0** | Q4 2026 | Advanced revocation and key lifecycle | Planning |

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

## v1.4.0 — Cross-Agent Tool Trust for A2A (Q2-Q3 2026)

When agents collaborate via A2A (Agent-to-Agent), tool schemas cross trust boundaries. SchemaPin v1.4.0 ensures that tool integrity verification extends seamlessly into A2A networks — every tool invoked through an A2A bridge is verified against its provider's signed schema.

### A2A Context for Schema Verification

| Item | Details |
|------|---------|
| `A2aVerificationContext` | New type wrapping `VerificationResult` with A2A caller identity, delegation depth, originating domain |
| `verify_schema_for_a2a()` | Extends `verify_schema_offline()` with A2A context validation |
| Domain scoping | Accept optional trusted domains list (from AgentPin `allowed_domains` constraints) |
| Intersection check | Scope verification to intersection of caller's allowed domains and tool provider's domain |

**Touchpoints:** new `src/a2a.rs`, extend `src/verification.rs`

### Trust Bundle Distribution for A2A Networks

| Item | Details |
|------|---------|
| Bundle signing | Sign trust bundles with a bundle authority key |
| `merge_trust_bundles()` | Combine bundles from multiple sources with deduplication (newest wins) |
| TOFU for bundles | TOFU pinning for bundle authority keys |
| JSON-RPC method | `schemapin/trustBundle` for A2A bundle exchange |

**Touchpoints:** extend `src/types/bundle.rs`, new `src/bundle_exchange.rs`

### Cross-Agent Tool Schema Caching

| Item | Details |
|------|---------|
| Cache key | `(tool_id, domain, schema_hash)` triple |
| Storage | In-memory with configurable TTL and max entries |
| Shared cache | Optional shared cache across agents in same runtime |

**Touchpoints:** new `src/cache.rs`

### Cross-Language Support

All four language implementations (Rust, JavaScript, Python, Go) receive matching implementations of:

- `A2aVerificationContext` and `verify_schema_for_a2a()`
- Trust bundle signing and `merge_trust_bundles()`
- Schema caching with TTL
- `schemapin/trustBundle` JSON-RPC helpers

---

## v1.5.0 — Advanced Revocation & Key Lifecycle (Q4 2026)

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
| Hardware-Backed Signing | HSM and TPM support for schema signing keys |
| Schema Evolution Tracking | Track schema changes over time with backward compatibility checks |
| Federated Trust Registries | Shared registries for cross-organization schema trust |
| Transparency Log | Append-only log of all schema signatures for auditability |

---

## Contributing

We welcome input on roadmap priorities:

- **GitHub Discussions** — Open a discussion in the [SchemaPin repository](https://github.com/nicholascross/SchemaPin/discussions)
- **Contributing Guide** — See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup
- **Security** — For security-sensitive feedback, see SECURITY.md

---

*Last updated: 2026-02-14*
