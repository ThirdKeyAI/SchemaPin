# SchemaPin

Cryptographic tool schema verification for AI agents and MCP servers. Prevent "MCP Rug Pull" attacks with ECDSA signatures, DNS-anchored trust, and TOFU key pinning.

**[Read the Documentation →](https://docs.schemapin.org)**

## What It Does

SchemaPin lets tool developers sign their schemas and skill folders with ECDSA P-256 keys, and lets AI agents verify that schemas haven't been tampered with. Public keys are discoverable via `.well-known/schemapin.json` (RFC 8615), and Trust-On-First-Use pinning protects against future key substitution.

- **ECDSA P-256 + SHA-256** cryptographic signatures
- **`.well-known` discovery** for public keys (RFC 8615)
- **TOFU key pinning** to prevent key substitution attacks
- **Key revocation** with standalone signed revocation documents and structured reasons
- **Trust bundles** for offline and air-gapped verification
- **Pluggable resolvers** — `.well-known`, local file, trust bundle, or chain
- **Skill folder signing** for AgentSkills (SKILL.md + file manifests)
- **Cross-language** — Python, JavaScript, Go, and Rust implementations

> **v1.4.0-alpha.2** (all four languages): three additive optional features — [signature expiration (`expires_at`)](https://docs.schemapin.org/signature-expiration/) with degraded-not-failed verification, [DNS TXT cross-verification](https://docs.schemapin.org/dns-txt/) at `_schemapin.{domain}` for second-channel trust, and [schema version binding (`schema_version` + `previous_hash`)](https://docs.schemapin.org/schema-version-binding/) for opt-in lineage chain enforcement that defends against rug-pull substitutions. v1.3 verifiers ignore the new fields; v1.4 verifiers handle both. The remaining v1.4 items (canonicalization id, A2A context, A2A trust bundles, scan-aware sigs, cross-agent schema cache) ship in subsequent alphas before stable v1.4.0.

## Quick Start

```python
from schemapin.crypto import KeyManager
from schemapin.utils import SchemaSigningWorkflow, SchemaVerificationWorkflow

# Sign a schema
private_key, public_key = KeyManager.generate_keypair()
signer = SchemaSigningWorkflow(KeyManager.export_private_key_pem(private_key))
signature = signer.sign_schema({"name": "my_tool", "parameters": {...}})

# Verify a schema
verifier = SchemaVerificationWorkflow()
result = verifier.verify_schema(schema, signature, "example.com/my_tool", "example.com")
```

**[Getting Started Guide →](https://docs.schemapin.org/getting-started/)**

## Installation

### Python

```bash
pip install schemapin
```

### JavaScript

```bash
npm install schemapin
```

### Go

```bash
go install github.com/ThirdKeyAi/schemapin/go/cmd/...@latest
```

### Rust

```toml
[dependencies]
schemapin = "1.3.0"
# v1.4.0-alpha.2 is also published — opt in for signature expiration,
# DNS TXT cross-verification, and schema version binding:
# schemapin = { version = "1.4.0-alpha.2", features = ["dns"] }
```

## Documentation

| Topic | Link |
|-------|------|
| Getting Started | [docs.schemapin.org/getting-started](https://docs.schemapin.org/getting-started/) |
| API Reference | [docs.schemapin.org/api-reference](https://docs.schemapin.org/api-reference/) |
| Skill Signing | [docs.schemapin.org/skill-signing](https://docs.schemapin.org/skill-signing/) |
| Trust Bundles | [docs.schemapin.org/trust-bundles](https://docs.schemapin.org/trust-bundles/) |
| Revocation | [docs.schemapin.org/revocation](https://docs.schemapin.org/revocation/) |
| Signature Expiration *(v1.4-alpha, all 4 langs)* | [docs.schemapin.org/signature-expiration](https://docs.schemapin.org/signature-expiration/) |
| DNS TXT Cross-Verification *(v1.4-alpha, all 4 langs)* | [docs.schemapin.org/dns-txt](https://docs.schemapin.org/dns-txt/) |
| Schema Version Binding *(v1.4-alpha, all 4 langs)* | [docs.schemapin.org/schema-version-binding](https://docs.schemapin.org/schema-version-binding/) |
| Deployment | [docs.schemapin.org/deployment](https://docs.schemapin.org/deployment/) |
| Troubleshooting | [docs.schemapin.org/troubleshooting](https://docs.schemapin.org/troubleshooting/) |
| Technical Specification | [TECHNICAL_SPECIFICATION.md](TECHNICAL_SPECIFICATION.md) |

## Project Structure

```
python/        # Python SDK (PyPI: schemapin)
javascript/    # JavaScript SDK (npm: schemapin)
go/            # Go SDK
rust/          # Rust SDK (crates.io: schemapin)
server/        # Production .well-known endpoint server
```

## License

MIT — Jascha Wanger / [ThirdKey.ai](https://thirdkey.ai)
