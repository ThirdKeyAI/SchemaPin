# Getting Started with SchemaPin

This guide walks you through installing SchemaPin, generating keys, signing a tool schema, and verifying it — in Python, JavaScript, Go, and Rust.

---

## Installation

### Python (PyPI)

```bash
pip install schemapin
```

CLI tools included: `schemapin-keygen`, `schemapin-sign`, `schemapin-verify`.

### JavaScript (npm)

```bash
npm install schemapin
```

### Go

```bash
go get github.com/ThirdKeyAi/schemapin/go@v1.3.0
```

CLI tools: `go install github.com/ThirdKeyAi/schemapin/go/cmd/...@v1.3.0`

### Rust (Cargo)

```toml
[dependencies]
schemapin = "1.3"
```

---

## Step 1: Generate a Key Pair

SchemaPin uses ECDSA P-256 exclusively. Generate a keypair in any language:

### Python

```python
from schemapin.crypto import KeyManager

private_key, public_key = KeyManager.generate_keypair()
private_key_pem = KeyManager.export_private_key_pem(private_key)
public_key_pem = KeyManager.export_public_key_pem(public_key)
```

### JavaScript

```javascript
import { KeyManager } from 'schemapin';

const { privateKey, publicKey } = KeyManager.generateKeypair();
const privateKeyPem = KeyManager.exportPrivateKeyPem(privateKey);
const publicKeyPem = KeyManager.exportPublicKeyPem(publicKey);
```

### Go

```go
import "github.com/ThirdKeyAi/schemapin/go/pkg/crypto"

km := crypto.NewKeyManager()
privKey, pubKey, err := km.GenerateKeypair()
privPem, _ := km.ExportPrivateKeyPEM(privKey)
pubPem, _ := km.ExportPublicKeyPEM(pubKey)
```

### Rust

```rust
use schemapin::crypto::generate_key_pair;

let key_pair = generate_key_pair()?;
// key_pair.private_key_pem — PEM-encoded private key
// key_pair.public_key_pem — PEM-encoded public key
```

### CLI

```bash
schemapin-keygen --output-dir ./keys
# Generates: private.pem, public.pem
```

---

## Step 2: Sign a Tool Schema

Schemas are canonicalized (sorted keys, no whitespace) before signing to ensure deterministic hashing.

### Python

```python
from schemapin.core import SchemaPinCore
from schemapin.crypto import SignatureManager

schema = {
    "name": "calculate_sum",
    "description": "Calculates the sum of two numbers",
    "parameters": {
        "type": "object",
        "properties": {
            "a": {"type": "number", "description": "First number"},
            "b": {"type": "number", "description": "Second number"},
        },
        "required": ["a", "b"],
    },
}

core = SchemaPinCore()
canonical = core.canonicalize_schema(schema)
signature = SignatureManager.sign_schema(private_key, canonical)
# signature is a Base64-encoded ECDSA signature
```

### JavaScript

```javascript
import { SchemaPinCore, SignatureManager } from 'schemapin';

const schema = {
    name: 'calculate_sum',
    description: 'Calculates the sum of two numbers',
    parameters: {
        type: 'object',
        properties: {
            a: { type: 'number', description: 'First number' },
            b: { type: 'number', description: 'Second number' },
        },
        required: ['a', 'b'],
    },
};

const core = new SchemaPinCore();
const canonical = core.canonicalizeSchema(schema);
const signature = await SignatureManager.signSchema(privateKey, canonical);
```

### Go

```go
import (
    "github.com/ThirdKeyAi/schemapin/go/pkg/core"
    "github.com/ThirdKeyAi/schemapin/go/pkg/crypto"
)

spc := core.NewSchemaPinCore()
canonical, _ := spc.CanonicalizeSchema(schema)
sig, _ := crypto.NewSignatureManager().SignSchema(privKey, canonical)
```

### Rust

```rust
use schemapin::core::SchemaPinCore;
use schemapin::crypto::{sign_data, generate_key_pair};

let core = SchemaPinCore::new();
let canonical = core.canonicalize_schema(&schema)?;
let signature = sign_data(&key_pair.private_key_pem, &canonical)?;
```

### CLI

```bash
schemapin-sign --key ./keys/private.pem --schema schema.json
# Outputs: Base64-encoded signature
```

---

## Step 3: Verify a Schema Signature

### Python

```python
from schemapin.crypto import SignatureManager

is_valid = SignatureManager.verify_signature(public_key, canonical, signature)
if is_valid:
    print("Schema signature is valid")
```

### JavaScript

```javascript
import { SignatureManager } from 'schemapin';

const isValid = await SignatureManager.verifySignature(publicKey, canonical, signature);
if (isValid) {
    console.log('Schema signature is valid');
}
```

### Go

```go
valid, err := crypto.NewSignatureManager().VerifySignature(pubKey, canonical, sig)
if valid {
    fmt.Println("Schema signature is valid")
}
```

### Rust

```rust
use schemapin::crypto::verify_signature;

let is_valid = verify_signature(&key_pair.public_key_pem, &canonical, &signature)?;
```

### CLI

```bash
schemapin-verify --key ./keys/public.pem --schema schema.json --signature sig.b64
```

---

## Step 4: Publish Your Public Key

Publish your public key at `/.well-known/schemapin.json` so clients can discover it:

### Python

```python
from schemapin.utils import create_well_known_response
from schemapin.crypto import KeyManager

response = create_well_known_response(
    public_key_pem=public_key_pem,
    developer_name="Acme Corp",
    schema_version="1.3",
    revocation_endpoint="https://example.com/.well-known/schemapin-revocations.json",
)

import json
with open(".well-known/schemapin.json", "w") as f:
    json.dump(response, f, indent=2)
```

### Discovery Document Format

```json
{
  "schema_version": "1.3",
  "developer_name": "Acme Corp",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0C...\n-----END PUBLIC KEY-----",
  "revoked_keys": [],
  "contact": "security@example.com",
  "revocation_endpoint": "https://example.com/.well-known/schemapin-revocations.json"
}
```

---

## Step 5: Full Verification Workflow

The complete workflow includes key discovery, signature verification, and TOFU key pinning:

### Python (Online)

```python
from schemapin.utils import SchemaVerificationWorkflow

workflow = SchemaVerificationWorkflow()

result = workflow.verify_schema(
    schema=schema,
    signature_b64=signature,
    tool_id="example.com/calculate_sum",
    domain="example.com",
    auto_pin=True,
)

if result["valid"]:
    print("Schema verified successfully")
    print(f"Key fingerprint: {result.get('key_fingerprint')}")
```

### Python (Offline)

```python
from schemapin.verification import verify_schema_offline, KeyPinStore

pin_store = KeyPinStore()

result = verify_schema_offline(
    schema=schema,
    signature_b64=signature,
    domain="example.com",
    tool_id="calculate_sum",
    discovery_data=discovery_doc,
    revocation_doc=None,
    pin_store=pin_store,
)
```

### JavaScript (Offline)

```javascript
import { verifySchemaOffline, KeyPinStore } from 'schemapin';

const pinStore = new KeyPinStore();

const result = verifySchemaOffline(
    schema,
    signatureB64,
    'example.com',
    'calculate_sum',
    discoveryData,
    null,
    pinStore,
);
```

---

## Step 6: Sign a Skill Directory (v1.3)

SchemaPin v1.3 adds SkillSigner for signing entire skill directories:

### Python

```python
from schemapin.skill import sign_skill, verify_skill_offline

# Sign a skill directory (writes .schemapin.sig)
sig = sign_skill("./my-skill/", private_key_pem, "example.com")

# Verify offline
from schemapin.verification import KeyPinStore
result = verify_skill_offline(
    "./my-skill/", discovery_data, sig, None, KeyPinStore()
)
```

### JavaScript

```javascript
import { signSkill, verifySkillOffline } from 'schemapin/skill';

const sig = await signSkill('./my-skill/', privateKeyPem, 'example.com');
const result = verifySkillOffline('./my-skill/', discoveryData, sig, null, pinStore);
```

---

## Next Steps

- [API Reference](api-reference.md) — Complete API across all 4 languages
- [Skill Signing](skill-signing.md) — SkillSigner deep dive
- [Trust Bundles](trust-bundles.md) — Offline and air-gapped verification
- [Deployment](deployment.md) — Serve `.well-known` endpoints in production
- [Troubleshooting](troubleshooting.md) — Common issues and solutions
