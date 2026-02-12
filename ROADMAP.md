# SchemaPin Roadmap

![Version](https://img.shields.io/badge/current-v1.2.0-brightgreen)
![Next](https://img.shields.io/badge/next-v1.3.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**Cryptographic schema integrity verification for AI tool ecosystems — the trust anchor of the ThirdKey trust stack.**

---

## Release Timeline

| Version | Target | Headline | Status |
|---------|--------|----------|--------|
| **1.0.0** | 2026-01 | Core verification, TOFU pinning, 4-language support | Shipped |
| **1.1.0** | 2026-01 | Revocation documents, standalone revocation endpoint | Shipped |
| **1.2.0** | 2026-02 | Offline verification, trust bundles, resolver abstraction | Shipped |
| **1.3.0** | Q2-Q3 2026 | Cross-agent tool trust for A2A networks | Planning |
| **1.4.0** | Q4 2026 | Advanced revocation and key lifecycle | Planning |

---

## v1.2.0 — Shipped

Offline verification for air-gapped environments, trust bundles for pre-distributing verified schemas, and `VerificationResolver` trait for pluggable resolution strategies. All four language implementations (Rust, JavaScript, Python, Go) updated.

See release notes for full details.

---

## v1.3.0 — Cross-Agent Tool Trust for A2A (Q2-Q3 2026)

When agents collaborate via A2A (Agent-to-Agent), tool schemas cross trust boundaries. SchemaPin v1.3.0 ensures that tool integrity verification extends seamlessly into A2A networks — every tool invoked through an A2A bridge is verified against its provider's signed schema.

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

## v1.4.0 — Advanced Revocation & Key Lifecycle (Q4 2026)

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

*Last updated: 2026-02-12*
