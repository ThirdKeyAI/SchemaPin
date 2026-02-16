# API Reference

Complete API reference for SchemaPin across all four language implementations.

---

## Key Management

### Generate Key Pair

Generate an ECDSA P-256 key pair for signing and verification.

| Language | Function | Returns |
|----------|----------|---------|
| Python | `KeyManager.generate_keypair()` | `(private_key, public_key)` — cryptography key objects |
| JavaScript | `KeyManager.generateKeypair()` | `{ privateKey, publicKey }` — Node.js crypto key objects |
| Go | `km.GenerateKeypair()` | `(*ecdsa.PrivateKey, *ecdsa.PublicKey, error)` |
| Rust | `generate_key_pair()` | `Result<KeyPair>` — `KeyPair { private_key_pem, public_key_pem }` |

#### Python

```python
from schemapin.crypto import KeyManager

private_key, public_key = KeyManager.generate_keypair()
```

#### JavaScript

```javascript
import { KeyManager } from 'schemapin';

const { privateKey, publicKey } = KeyManager.generateKeypair();
```

#### Go

```go
km := crypto.NewKeyManager()
privKey, pubKey, err := km.GenerateKeypair()
```

#### Rust

```rust
let key_pair = generate_key_pair()?;
```

---

### Export Keys to PEM

| Language | Function | Returns |
|----------|----------|---------|
| Python | `KeyManager.export_private_key_pem(key)` / `export_public_key_pem(key)` | `str` — PEM string |
| JavaScript | `KeyManager.exportPrivateKeyPem(key)` / `exportPublicKeyPem(key)` | `string` — PEM string |
| Go | `km.ExportPrivateKeyPEM(key)` / `km.ExportPublicKeyPEM(key)` | `(string, error)` |
| Rust | Already PEM in `KeyPair` | `String` |

#### Python

```python
private_key_pem = KeyManager.export_private_key_pem(private_key)
public_key_pem = KeyManager.export_public_key_pem(public_key)
```

#### JavaScript

```javascript
const privateKeyPem = KeyManager.exportPrivateKeyPem(privateKey);
const publicKeyPem = KeyManager.exportPublicKeyPem(publicKey);
```

---

### Load Keys from PEM

| Language | Function | Returns |
|----------|----------|---------|
| Python | `KeyManager.load_private_key_pem(pem)` / `load_public_key_pem(pem)` | Key object |
| JavaScript | `KeyManager.loadPrivateKeyPem(pem)` / `loadPublicKeyPem(pem)` | Key object |
| Go | `km.LoadPrivateKeyPEM(pem)` / `km.LoadPublicKeyPEM(pem)` | Key object |
| Rust | Functions accept PEM strings directly | — |

#### Python

```python
private_key = KeyManager.load_private_key_pem(pem_string)
public_key = KeyManager.load_public_key_pem(pem_string)
```

---

## Schema Operations

### Canonicalize Schema

Convert a schema to its canonical (deterministic) JSON form for hashing. Keys are sorted lexicographically, whitespace removed, UTF-8 encoded.

| Language | Function | Parameters | Returns |
|----------|----------|-----------|---------|
| Python | `SchemaPinCore().canonicalize_schema(schema)` | `dict` | `str` — canonical JSON |
| JavaScript | `new SchemaPinCore().canonicalizeSchema(schema)` | `object` | `string` — canonical JSON |
| Go | `spc.CanonicalizeSchema(schema)` | `interface{}` | `(string, error)` |
| Rust | `SchemaPinCore::new().canonicalize_schema(schema)` | `&Value` | `Result<String>` |

#### Python

```python
from schemapin.core import SchemaPinCore

core = SchemaPinCore()
canonical = core.canonicalize_schema({
    "name": "my_tool",
    "description": "Does something",
    "parameters": {"type": "object"},
})
# Returns: '{"description":"Does something","name":"my_tool","parameters":{"type":"object"}}'
```

#### JavaScript

```javascript
import { SchemaPinCore } from 'schemapin';

const core = new SchemaPinCore();
const canonical = core.canonicalizeSchema(schema);
```

**Canonicalization rules:**
1. UTF-8 encoding
2. All insignificant whitespace removed
3. Keys sorted lexicographically (recursive)
4. Strict JSON serialization

---

## Signature Operations

### Sign Schema

Create an ECDSA P-256 signature over canonicalized schema content.

| Language | Function | Returns |
|----------|----------|---------|
| Python | `SignatureManager.sign_schema(private_key, canonical)` | `str` — Base64-encoded signature |
| JavaScript | `SignatureManager.signSchema(privateKey, canonical)` | `Promise<string>` — Base64-encoded |
| Go | `sm.SignSchema(privKey, canonical)` | `(string, error)` — Base64-encoded |
| Rust | `sign_data(private_key_pem, canonical)` | `Result<String>` — Base64-encoded |

#### Python

```python
from schemapin.crypto import SignatureManager

signature = SignatureManager.sign_schema(private_key, canonical)
```

#### JavaScript

```javascript
import { SignatureManager } from 'schemapin';

const signature = await SignatureManager.signSchema(privateKey, canonical);
```

#### Go

```go
sm := crypto.NewSignatureManager()
sig, err := sm.SignSchema(privKey, canonical)
```

#### Rust

```rust
let signature = sign_data(&key_pair.private_key_pem, &canonical)?;
```

---

### Verify Signature

Verify an ECDSA P-256 signature against canonicalized content.

| Language | Function | Returns |
|----------|----------|---------|
| Python | `SignatureManager.verify_signature(public_key, canonical, signature)` | `bool` |
| JavaScript | `SignatureManager.verifySignature(publicKey, canonical, signature)` | `Promise<boolean>` |
| Go | `sm.VerifySignature(pubKey, canonical, sig)` | `(bool, error)` |
| Rust | `verify_signature(public_key_pem, canonical, signature)` | `Result<bool>` |

#### Python

```python
is_valid = SignatureManager.verify_signature(public_key, canonical, signature)
```

#### JavaScript

```javascript
const isValid = await SignatureManager.verifySignature(publicKey, canonical, signature);
```

---

## Public Key Discovery

### Fetch Well-Known Document

Retrieve a developer's public key from their `.well-known/schemapin.json` endpoint.

| Language | Function | Returns |
|----------|----------|---------|
| Python | `PublicKeyDiscovery.fetch_well_known(domain)` | `dict` — discovery document |
| JavaScript | `PublicKeyDiscovery.fetchWellKnown(domain)` | `Promise<object>` |
| Go | `FetchWellKnown(domain)` | `(*DiscoveryDocument, error)` |
| Rust | `WellKnownResolver::resolve(domain)` (fetch feature) | `Result<DiscoveryDocument>` |

#### Python

```python
from schemapin.discovery import PublicKeyDiscovery

discovery = PublicKeyDiscovery.fetch_well_known("example.com")
public_key_pem = discovery["public_key_pem"]
developer_name = discovery["developer_name"]
```

---

## Key Pinning (TOFU)

### KeyPinStore

Manages Trust-On-First-Use key pinning. Stores SHA-256 fingerprints of public keys indexed by domain.

#### Python

```python
from schemapin.pinning import KeyPinStore

store = KeyPinStore()

# Pin a key (returns True if first use, raises if changed)
store.pin_key("example.com", public_key_pem)

# Check if a domain has a pinned key
is_pinned = store.is_pinned("example.com")

# Get the pinned fingerprint
fingerprint = store.get_fingerprint("example.com")

# Serialize / deserialize
data = store.to_dict()
restored = KeyPinStore.from_dict(data)
```

#### JavaScript

```javascript
import { KeyPinStore } from 'schemapin';

const store = new KeyPinStore();
store.pinKey('example.com', publicKeyPem);
const isPinned = store.isPinned('example.com');
const fingerprint = store.getFingerprint('example.com');

// Serialize / deserialize
const json = store.toJson();
const restored = KeyPinStore.fromJson(json);
```

---

## Verification Workflows

### Online Verification

Full workflow with HTTP discovery, signature verification, and TOFU pinning.

#### Python

```python
from schemapin.utils import SchemaVerificationWorkflow

workflow = SchemaVerificationWorkflow()
result = workflow.verify_schema(schema, signature_b64, "example.com/tool", "example.com")
# result = { "valid": True/False, "key_fingerprint": "...", "error": "..." }
```

### Offline Verification

Verify without HTTP calls using pre-fetched discovery data.

#### Python

```python
from schemapin.verification import verify_schema_offline, KeyPinStore

result = verify_schema_offline(
    schema, signature_b64, "example.com", "tool_id",
    discovery_data, revocation_doc, KeyPinStore(),
)
```

#### JavaScript

```javascript
import { verifySchemaOffline, KeyPinStore } from 'schemapin';

const result = verifySchemaOffline(
    schema, signatureB64, 'example.com', 'tool_id',
    discoveryData, revocationDoc, new KeyPinStore(),
);
```

#### Go

```go
result := verification.VerifySchemaOffline(
    schema, signatureB64, "example.com", "tool_id",
    discoveryData, revocationDoc, pinStore,
)
```

#### Rust

```rust
let result = verify_schema_offline(
    &schema, &signature_b64, "example.com", "tool_id",
    &discovery_data, revocation_doc.as_ref(), Some(&pin_store),
);
```

### Resolver-Based Verification

Use pluggable resolvers for flexible discovery (v1.2.0+).

#### Python

```python
from schemapin.verification import verify_schema_with_resolver
from schemapin.resolver import ChainResolver, TrustBundleResolver, WellKnownResolver

resolver = ChainResolver([
    TrustBundleResolver.from_json(bundle_json),
    WellKnownResolver(timeout=10),
])

result = verify_schema_with_resolver(
    schema, signature_b64, "example.com", "tool_id",
    resolver, pin_store,
)
```

---

## Revocation

### Build Revocation Document

#### Python

```python
from schemapin.revocation import (
    build_revocation_document,
    add_revoked_key,
    check_revocation,
    RevocationReason,
)

doc = build_revocation_document("example.com")
add_revoked_key(doc, fingerprint, RevocationReason.KEY_COMPROMISE)
check_revocation(doc, some_fingerprint)  # raises if revoked
```

---

## Skill Signing (v1.3.0)

### Sign a Skill Directory

| Language | Function | Returns |
|----------|----------|---------|
| Python | `sign_skill(path, private_key_pem, domain)` | `SkillSignature` — writes `.schemapin.sig` |
| JavaScript | `signSkill(path, privateKeyPem, domain)` | `Promise<SkillSignature>` |
| Go | `skill.SignSkill(path, privKeyPem, domain, "", "")` | `(*SkillSignature, error)` |
| Rust | `sign_skill(path, private_key_pem, domain, None, None)` | `Result<SkillSignature>` |

### Verify a Skill Directory

| Language | Function | Returns |
|----------|----------|---------|
| Python | `verify_skill_offline(path, discovery, sig, revocation, pin_store)` | Verification result |
| JavaScript | `verifySkillOffline(path, discovery, sig, revocation, pinStore)` | Verification result |
| Go | `skill.VerifySkillOffline(path, disc, sig, rev, pinStore, "")` | Verification result |
| Rust | `verify_skill_offline(path, disc, sig, rev, pin_store, None)` | `Result<VerificationResult>` |

### Detect Tampered Files

| Language | Function | Returns |
|----------|----------|---------|
| Python | `detect_tampered_files(current, original)` | `TamperResult` — `.modified`, `.added`, `.removed` |
| JavaScript | `detectTamperedFiles(current, original)` | `{ modified, added, removed }` |
| Go | `skill.DetectTamperedFiles(current, original)` | `*TamperResult` |
| Rust | `detect_tampered_files(current, original)` | `TamperResult` |

See [Skill Signing](skill-signing.md) for detailed usage.
