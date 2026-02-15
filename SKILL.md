# SchemaPin Development Skills Guide

**Purpose**: This guide helps AI assistants quickly integrate SchemaPin into applications for cryptographic tool schema verification.

**For Full Documentation**: See the [README](https://github.com/ThirdKeyAI/SchemaPin/blob/main/README.md), [Technical Specification](https://github.com/ThirdKeyAI/SchemaPin/blob/main/TECHNICAL_SPECIFICATION.md), and language-specific READMEs in each subdirectory.

## What SchemaPin Does

SchemaPin prevents "MCP Rug Pull" attacks by enabling developers to cryptographically sign their tool schemas (ECDSA P-256 + SHA-256) and clients to verify schemas haven't been tampered with. It uses Trust-On-First-Use (TOFU) key pinning and RFC 8615 `.well-known` endpoints for public key discovery.

**Part of the ThirdKey trust stack**: SchemaPin (tool integrity) → AgentPin (agent identity) → Symbiont (runtime)

---

## Quick Start by Language

### Python

```bash
pip install schemapin
```

```python
from schemapin.crypto import KeyManager, SignatureManager
from schemapin.core import SchemaPinCore

# Generate keys
private_key, public_key = KeyManager.generate_keypair()

# Sign a schema
core = SchemaPinCore()
canonical = core.canonicalize_schema(schema_dict)
signature = SignatureManager.sign_schema(private_key, canonical)

# Verify
is_valid = SignatureManager.verify_signature(public_key, canonical, signature)
```

### JavaScript

```bash
npm install schemapin
```

```javascript
import { KeyManager, SignatureManager, SchemaPinCore } from 'schemapin';

// Generate keys
const { privateKey, publicKey } = KeyManager.generateKeypair();

// Sign a schema
const core = new SchemaPinCore();
const canonical = core.canonicalizeSchema(schema);
const signature = await SignatureManager.signSchema(privateKey, canonical);

// Verify
const isValid = await SignatureManager.verifySignature(publicKey, canonical, signature);
```

### Go

```bash
go get github.com/ThirdKeyAi/schemapin/go@v1.3.0
```

```go
import (
    "github.com/ThirdKeyAi/schemapin/go/pkg/core"
    "github.com/ThirdKeyAi/schemapin/go/pkg/crypto"
)

// Generate keys
km := crypto.NewKeyManager()
privKey, pubKey, _ := km.GenerateKeypair()

// Sign a schema
spc := core.NewSchemaPinCore()
canonical, _ := spc.CanonicalizeSchema(schema)
sig, _ := crypto.NewSignatureManager().SignSchema(privKey, canonical)

// Verify
valid, _ := crypto.NewSignatureManager().VerifySignature(pubKey, canonical, sig)
```

### Rust

```toml
[dependencies]
schemapin = "1.3"
```

```rust
use schemapin::crypto::{generate_key_pair, sign_data, verify_signature};
use schemapin::core::SchemaPinCore;

// Generate keys
let key_pair = generate_key_pair()?;

// Sign
let core = SchemaPinCore::new();
let canonical = core.canonicalize_schema(&schema)?;
let signature = sign_data(&key_pair.private_key_pem, &canonical)?;

// Verify
let is_valid = verify_signature(&key_pair.public_key_pem, &canonical, &signature)?;
```

---

## Core Concepts

### 1. Schema Canonicalization

Schemas are canonicalized (deterministic JSON serialization with sorted keys) before hashing. This ensures identical schemas always produce the same hash regardless of key ordering.

### 2. `.well-known` Discovery

Developers publish their public key at `https://example.com/.well-known/schemapin.json`:

```python
from schemapin.utils import create_well_known_response

response = create_well_known_response(
    public_key_pem=public_key_pem,
    developer_name="Acme Corp",
    schema_version="1.2",
    revocation_endpoint="https://example.com/.well-known/schemapin-revocations.json"
)
```

### 3. TOFU Key Pinning

On first verification, the developer's public key fingerprint is pinned. Subsequent verifications reject different keys for the same domain — detecting key substitution attacks.

### 4. Verification Workflows

**Online** (standard):
```python
workflow = SchemaVerificationWorkflow(pin_store)
result = workflow.verify_schema(schema, signature, "https://example.com")
```

**Offline** (v1.2.0 — no HTTP required):
```python
from schemapin.verification import verify_schema_offline, KeyPinStore

pin_store = KeyPinStore()
result = verify_schema_offline(
    schema, signature_b64, domain, tool_id,
    discovery_data, revocation_doc, pin_store
)
```

---

## v1.2.0 Features

### Standalone Revocation Documents

```python
from schemapin.revocation import (
    build_revocation_document, add_revoked_key,
    check_revocation, RevocationReason
)

doc = build_revocation_document("example.com")
add_revoked_key(doc, fingerprint, RevocationReason.KEY_COMPROMISE)
check_revocation(doc, some_fingerprint)  # raises if revoked
```

### Trust Bundles (Offline / Air-Gapped)

Pre-package discovery + revocation data for environments without internet:

```python
from schemapin.bundle import SchemaPinTrustBundle

bundle = SchemaPinTrustBundle.from_json(bundle_json_str)
discovery = bundle.find_discovery("example.com")
revocation = bundle.find_revocation("example.com")
```

### Pluggable Discovery Resolvers

```python
from schemapin.resolver import (
    WellKnownResolver,    # HTTP .well-known lookups
    LocalFileResolver,    # Local JSON files
    TrustBundleResolver,  # In-memory trust bundles
    ChainResolver,        # First-match fallthrough
)

# Chain: try bundle first, fall back to HTTP
resolver = ChainResolver([
    TrustBundleResolver.from_json(bundle_json),
    WellKnownResolver(timeout=10),
])
```

### Resolver-Based Verification

```python
from schemapin.verification import verify_schema_with_resolver

result = verify_schema_with_resolver(
    schema, signature_b64, domain, tool_id,
    resolver, pin_store
)
```

---

## v1.3.0 Features

### SkillSigner — File-Based Skill Folder Signing

Sign entire skill directories (e.g., a folder containing `SKILL.md`) with ECDSA P-256. Produces a `.schemapin.sig` manifest alongside the files, proving no file has been tampered with.

**Python:**
```python
from schemapin.skill import sign_skill, verify_skill_offline

# Sign a skill directory
sig = sign_skill("./my-skill/", private_key_pem, "example.com")
# Writes .schemapin.sig into ./my-skill/

# Verify offline
from schemapin.verification import KeyPinStore
result = verify_skill_offline("./my-skill/", discovery_data, sig, revocation_doc, KeyPinStore())
```

**JavaScript:**
```javascript
import { signSkill, verifySkillOffline } from 'schemapin/skill';

const sig = await signSkill('./my-skill/', privateKeyPem, 'example.com');
const result = verifySkillOffline('./my-skill/', discoveryData, sig, revDoc, pinStore);
```

**Go:**
```go
import "github.com/ThirdKeyAi/schemapin/go/pkg/skill"

sig, err := skill.SignSkill("./my-skill/", privateKeyPEM, "example.com", "", "")
result := skill.VerifySkillOffline("./my-skill/", disc, sig, rev, pinStore, "")
```

**Rust:**
```rust
use schemapin::skill::{sign_skill, verify_skill_offline};

let sig = sign_skill("./my-skill/", &private_key_pem, "example.com", None, None)?;
let result = verify_skill_offline("./my-skill/", &disc, Some(&sig), rev.as_ref(), Some(&pin_store), None);
```

### `.schemapin.sig` Format

```json
{
  "schemapin_version": "1.3",
  "skill_name": "my-skill",
  "skill_hash": "sha256:<root_hash>",
  "signature": "<base64_ecdsa_signature>",
  "signed_at": "2026-02-14T00:00:00Z",
  "domain": "example.com",
  "signer_kid": "sha256:<key_fingerprint>",
  "file_manifest": {
    "SKILL.md": "sha256:<file_hash>"
  }
}
```

### Tamper Detection

```python
from schemapin.skill import detect_tampered_files, canonicalize_skill

_, current_manifest = canonicalize_skill("./my-skill/")
tampered = detect_tampered_files(current_manifest, sig.file_manifest)
# tampered.modified, tampered.added, tampered.removed
```

---

## Server-Side Setup

### Publishing `.well-known` Endpoints

Python CLI tools are included:

```bash
# Generate a keypair
schemapin-keygen --output-dir ./keys

# Sign a schema
schemapin-sign --key ./keys/private.pem --schema schema.json

# Verify a signature
schemapin-verify --key ./keys/public.pem --schema schema.json --signature sig.b64
```

Go CLI equivalents are also available (`go install github.com/ThirdKeyAi/schemapin/go/cmd/...@v1.3.0`).

---

## Architecture

```
Developer                          Client (AI Platform)
─────────                          ────────────────────
1. Generate ECDSA P-256 keypair
2. Publish public key at           3. Discover public key from
   /.well-known/schemapin.json        /.well-known/schemapin.json
4. Sign tool schema                5. Verify signature
   (canonicalize → SHA-256            (canonicalize → SHA-256
    → ECDSA sign)                      → ECDSA verify)
                                   6. TOFU pin the key fingerprint
                                   7. Check revocation status
```

---

## Language API Reference

| Operation | Python | JavaScript | Go | Rust |
|-----------|--------|------------|----|----|
| Generate keys | `KeyManager.generate_keypair()` | `KeyManager.generateKeypair()` | `km.GenerateKeypair()` | `generate_key_pair()` |
| Sign schema | `SignatureManager.sign_schema()` | `SignatureManager.signSchema()` | `sm.SignSchema()` | `sign_data()` |
| Verify signature | `SignatureManager.verify_signature()` | `SignatureManager.verifySignature()` | `sm.VerifySignature()` | `verify_signature()` |
| Canonicalize | `SchemaPinCore().canonicalize_schema()` | `new SchemaPinCore().canonicalizeSchema()` | `spc.CanonicalizeSchema()` | `SchemaPinCore::new().canonicalize_schema()` |
| Discover key | `PublicKeyDiscovery.fetch_well_known()` | `PublicKeyDiscovery.fetchWellKnown()` | `FetchWellKnown()` | `WellKnownResolver` (fetch feature) |
| Offline verify | `verify_schema_offline()` | `verifySchemaOffline()` | `VerifySchemaOffline()` | `verify_schema_offline()` |
| Resolver verify | `verify_schema_with_resolver()` | `verifySchemaWithResolver()` | `VerifySchemaWithResolver()` | `verify_schema_with_resolver()` |
| Sign skill folder | `sign_skill()` | `signSkill()` | `skill.SignSkill()` | `sign_skill()` |
| Verify skill | `verify_skill_offline()` | `verifySkillOffline()` | `skill.VerifySkillOffline()` | `verify_skill_offline()` |
| Detect tampering | `detect_tampered_files()` | `detectTamperedFiles()` | `skill.DetectTamperedFiles()` | `detect_tampered_files()` |

---

## Testing

```bash
# Python
cd python && python -m pytest tests/ -v

# JavaScript
cd javascript && npm test

# Go
cd go && go test ./...

# Rust
cd rust && cargo test
```

---

## Pro Tips for AI Assistants

1. **Always canonicalize** before signing or verifying — raw JSON comparison will fail
2. **Use offline verification** when you have pre-fetched discovery data — avoids HTTP calls during schema validation
3. **Trust bundles** are ideal for CI/CD and air-gapped deployments
4. **ChainResolver** lets you layer resolvers: bundle → local files → HTTP as fallback
5. **TOFU pinning** means the first key seen for a domain is trusted — warn users on key changes
6. **All languages use the same crypto** — ECDSA P-256 + SHA-256, so cross-language verification works
7. **Revocation checking** should always be performed — both simple lists and standalone documents
8. **SkillSigner** signs entire directories — ideal for SKILL.md folders uploaded to registries like ClaWHub
9. **`.schemapin.sig`** is auto-excluded from hashing — you can re-sign a directory without removing the old signature first
