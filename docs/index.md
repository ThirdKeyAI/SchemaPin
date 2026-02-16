# SchemaPin

**Cryptographic tool schema verification to prevent MCP Rug Pull attacks.**

SchemaPin is the tool integrity layer of the [ThirdKey](https://thirdkey.ai) trust stack: **SchemaPin** (tool integrity) → [AgentPin](https://agentpin.org) (agent identity) → [Symbiont](https://symbiont.dev) (runtime).

---

## What SchemaPin Does

SchemaPin enables developers to cryptographically sign tool schemas (ECDSA P-256 + SHA-256) and clients to verify schemas haven't been tampered with. It uses Trust-On-First-Use (TOFU) key pinning and `.well-known` endpoints for public key discovery.

- **Schema Signing** — ECDSA P-256 signatures over canonicalized JSON schemas
- **Verification** — Signature verification with public key discovery and TOFU pinning
- **Skill Signing** — Sign entire skill directories with `.schemapin.sig` manifests (v1.3)
- **Trust Bundles** — Offline verification with pluggable discovery resolvers (v1.2)
- **Revocation** — Key and schema revocation with standalone documents

## Quick Example

```python
from schemapin.crypto import KeyManager, SignatureManager
from schemapin.core import SchemaPinCore

# Generate keys
private_key, public_key = KeyManager.generate_keypair()

# Sign a schema
schema = {"name": "calculate_sum", "description": "Adds two numbers",
          "parameters": {"type": "object", "properties": {
              "a": {"type": "number"}, "b": {"type": "number"}},
              "required": ["a", "b"]}}

core = SchemaPinCore()
canonical = core.canonicalize_schema(schema)
signature = SignatureManager.sign_schema(private_key, canonical)

# Verify
is_valid = SignatureManager.verify_signature(public_key, canonical, signature)
print(f"Valid: {is_valid}")
```

## Implementations

| Language | Package | Install |
|----------|---------|---------|
| **Python** | `schemapin` | `pip install schemapin` |
| **JavaScript** | `schemapin` | `npm install schemapin` |
| **Go** | `github.com/ThirdKeyAi/schemapin/go` | `go get github.com/ThirdKeyAi/schemapin/go@v1.3.0` |
| **Rust** | `schemapin` | `cargo add schemapin` |

All four implementations use identical crypto (ECDSA P-256 + SHA-256) — cross-language verification works out of the box.

## Documentation

| Guide | Description |
|-------|-------------|
| [Getting Started](getting-started.md) | Install, sign, and verify across all 4 languages |
| [API Reference](api-reference.md) | Complete API with function signatures and examples |
| [Skill Signing](skill-signing.md) | Sign and verify skill directories (v1.3) |
| [Trust Bundles](trust-bundles.md) | Offline verification and pluggable resolvers |
| [Deployment](deployment.md) | Serve `.well-known` endpoints in production |
| [Troubleshooting](troubleshooting.md) | Common issues and solutions |

## Links

- [GitHub](https://github.com/ThirdKeyAI/SchemaPin)
- [Website](https://schemapin.org)
- [Verify a Domain](https://schemapin.org/verify.html)
- [Technical Specification](https://github.com/ThirdKeyAI/SchemaPin/blob/main/TECHNICAL_SPECIFICATION.md)
