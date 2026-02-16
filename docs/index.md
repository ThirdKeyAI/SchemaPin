# SchemaPin

**Cryptographic integrity for AI tool schemas and skill directories — signing, verification, TOFU pinning, and trust bundles.**

SchemaPin is the tool integrity layer of the [ThirdKey](https://thirdkey.ai) trust stack: **SchemaPin** (tool integrity) → [AgentPin](https://agentpin.org) (agent identity) → [Symbiont](https://symbiont.dev) (runtime).

---

## What SchemaPin Does

SchemaPin enables developers to cryptographically sign tool schemas and skill directories (ECDSA P-256 + SHA-256) and clients to verify they haven't been tampered with. It uses Trust-On-First-Use (TOFU) key pinning and `.well-known` endpoints for public key discovery.

- **Schema Signing** — ECDSA P-256 signatures over canonicalized JSON tool schemas
- **Skill Directory Signing** — Sign entire skill directories, producing a `.schemapin.sig` manifest that covers every file
- **Verification** — Signature verification with public key discovery and TOFU pinning
- **Trust Bundles** — Offline verification with pluggable discovery resolvers
- **Revocation** — Key and schema revocation with standalone documents

## Quick Examples

### Sign a Tool Schema

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

### Sign a Skill Directory

```python
from schemapin.skill import sign_skill, verify_skill_offline
from schemapin.verification import KeyPinStore

# Sign all files in a skill directory (writes .schemapin.sig)
sig = sign_skill("./my-skill/", private_key_pem, "example.com")
print(f"Signed {len(sig.file_manifest)} files, root hash: {sig.skill_hash}")

# Verify the skill hasn't been tampered with
result = verify_skill_offline("./my-skill/", discovery_doc, sig, None, KeyPinStore())
print(f"Verified: {result.valid}")
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
