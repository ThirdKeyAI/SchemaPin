# Troubleshooting

Common issues and solutions when working with SchemaPin.

---

## Signature Verification Failures

### Signature is Invalid

**Problem:** `verify_signature()` returns `False` or verification fails.

**Common causes:**

1. **Schema not canonicalized** — You must canonicalize before verifying

```python
from schemapin.core import SchemaPinCore

core = SchemaPinCore()

# WRONG: verifying against raw JSON
is_valid = SignatureManager.verify_signature(key, raw_json, sig)  # May fail

# CORRECT: canonicalize first
canonical = core.canonicalize_schema(schema_dict)
is_valid = SignatureManager.verify_signature(key, canonical, sig)  # Correct
```

2. **Wrong key** — Signature was created with a different private key

```bash
# Verify which key signed the schema
# The signature is tied to a specific private key
# Ensure the public key matches the private key used for signing
```

3. **Schema modified after signing** — Any change (even whitespace) invalidates the signature

```python
# Canonicalization makes this deterministic:
# { "b": 1, "a": 2 } and { "a": 2, "b": 1 } produce the same canonical form
# But { "a": 2, "b": 1, "c": 3 } is a different schema
```

---

### Wrong Algorithm

**Problem:** Verification fails because the key is not ECDSA P-256.

SchemaPin only supports ECDSA with P-256 (secp256r1). RSA, Ed25519, and other algorithms are not accepted.

```python
# Check your key type
from schemapin.crypto import KeyManager

key = KeyManager.load_public_key_pem(pem_string)
# Should be an EC key with P-256 curve
```

---

## Key Discovery Issues

### Cannot Fetch `.well-known/schemapin.json`

**Debug steps:**

```bash
# 1. Check if the URL is accessible
curl -sv https://example.com/.well-known/schemapin.json

# 2. Check for redirects (should NOT redirect)
curl -sI https://example.com/.well-known/schemapin.json | head -5

# 3. Check Content-Type header
curl -sI https://example.com/.well-known/schemapin.json | grep -i content-type
# Expected: application/json

# 4. Validate the JSON
curl -s https://example.com/.well-known/schemapin.json | python -m json.tool
```

**Common causes:**

- **No HTTPS** — Discovery must be over HTTPS
- **Redirect** — The URL redirects (HTTP→HTTPS or www→non-www)
- **404** — File not placed in correct location
- **CORS** — Browser-based clients need `Access-Control-Allow-Origin` header

---

### Invalid PEM Key in Discovery Document

**Problem:** The `public_key_pem` field doesn't contain a valid PEM key.

```bash
# Extract and validate the PEM key
curl -s https://example.com/.well-known/schemapin.json | \
  jq -r '.public_key_pem' | \
  openssl ec -pubin -text -noout
```

**Common issues:**
- Missing newlines in PEM (JSON requires `\n` escape)
- Incorrect key type (RSA instead of EC)
- Truncated key

**Correct PEM in JSON:**
```json
{
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----"
}
```

---

## TOFU Key Pinning Issues

### Key Changed Error

**Problem:** Verification fails because the key for a domain has changed since it was first pinned.

**This is a security feature.** Possible causes:

1. **Legitimate key rotation** — Developer rotated their key
2. **Attack** — Someone is serving a different key

**Resolution:**

```python
from schemapin.pinning import KeyPinStore

# If the key change is legitimate, update the pin:
store = KeyPinStore.from_dict(existing_pins)

# Option 1: Remove the old pin and re-verify
store.remove_pin("example.com")
# Next verification will pin the new key

# Option 2: Check if old key is in revoked_keys
# If the old key fingerprint appears in the discovery document's
# revoked_keys list, the rotation is expected
```

### Lost Pin Store

**Problem:** Pin store file was deleted or corrupted.

**Impact:** All domains will be treated as first-use again. This is safe but loses protection against key substitution for previously verified domains.

**Prevention:** Back up your pin store regularly:

```python
# Save pin store
data = store.to_dict()
import json
with open("pins-backup.json", "w") as f:
    json.dump(data, f)
```

---

## Canonicalization Issues

### Different Hashes for Same Schema

**Problem:** The same logical schema produces different canonical forms.

**Cause:** Schemas contain values that differ in representation:

```python
# These are different to the canonicalizer:
schema1 = {"count": 1}    # integer
schema2 = {"count": 1.0}  # float

# These are the same after canonicalization:
schema1 = {"a": 1, "b": 2}
schema2 = {"b": 2, "a": 1}  # Keys reordered → same canonical form
```

**Solution:** Ensure schema values are consistent types. The canonicalizer sorts keys but does not normalize value types.

---

### Unicode Issues

**Problem:** Schemas with Unicode characters produce unexpected canonical forms.

**Solution:** SchemaPin uses UTF-8 encoding consistently. Ensure your schema is valid UTF-8:

```python
# Verify encoding
canonical = core.canonicalize_schema(schema)
assert isinstance(canonical, str)  # Should be a Python str (UTF-8)
```

---

## Skill Signing Issues

### `.schemapin.sig` Not Found

**Problem:** `verify_skill_offline()` fails because `.schemapin.sig` doesn't exist.

**Solution:** Sign the skill directory first:

```python
from schemapin.skill import sign_skill

sign_skill("./my-skill/", private_key_pem, "example.com")
# Creates ./my-skill/.schemapin.sig
```

### Tampered Files Detected

**Problem:** Verification fails because files have changed since signing.

**Debug:** Check which files changed:

```python
from schemapin.skill import detect_tampered_files, canonicalize_skill
import json

# Load the original signature
sig = json.load(open("./my-skill/.schemapin.sig"))

# Get current state
_, current_manifest = canonicalize_skill("./my-skill/")

# Compare
tampered = detect_tampered_files(current_manifest, sig["file_manifest"])
print(f"Modified: {tampered.modified}")
print(f"Added: {tampered.added}")
print(f"Removed: {tampered.removed}")
```

**Solution:** Re-sign the skill after modifications:

```python
sign_skill("./my-skill/", private_key_pem, "example.com")
```

---

## Cross-Language Issues

### Signature from Python Fails in JavaScript (or Vice Versa)

All four SchemaPin implementations use the same cryptographic primitives and should interoperate. If cross-language verification fails:

1. **Check canonicalization** — Both sides must canonicalize the same way

```python
# Python canonical
from schemapin.core import SchemaPinCore
canonical_py = SchemaPinCore().canonicalize_schema(schema)
print(repr(canonical_py))
```

```javascript
// JavaScript canonical
const canonical_js = new SchemaPinCore().canonicalizeSchema(schema);
console.log(JSON.stringify(canonical_js));
```

2. **Check signature encoding** — All implementations use Base64-encoded signatures

3. **Check key format** — PEM keys must be identical (including header/footer lines)

---

## Trust Bundle Issues

### Domain Not Found in Bundle

```python
from schemapin.bundle import SchemaPinTrustBundle

bundle = SchemaPinTrustBundle.from_json(bundle_json)
discovery = bundle.find_discovery("example.com")

if discovery is None:
    # List available domains
    for entry in bundle.entries:
        print(f"  - {entry['domain']}")
```

### Stale Bundle

**Problem:** Bundle contains outdated keys or missing revocations.

**Solution:** Rebuild the bundle regularly:

```bash
#!/bin/bash
# Fetch fresh documents and rebuild bundle
for domain in example.com partner.com; do
    curl -s "https://$domain/.well-known/schemapin.json" > "/tmp/$domain.json"
done

python -c "
from schemapin.bundle import SchemaPinTrustBundle
import json

bundle = SchemaPinTrustBundle()
for domain in ['example.com', 'partner.com']:
    disc = json.load(open(f'/tmp/{domain}.json'))
    bundle.add_entry(domain, disc, None)

with open('trust-bundle.json', 'w') as f:
    f.write(bundle.to_json())
"
```

---

## Performance Issues

### Slow Verification Due to HTTP

**Problem:** Online verification is slow because it fetches discovery documents on every call.

**Solutions:**

1. **Cache discovery documents** — Use a resolver with caching
2. **Use offline verification** — Pre-fetch and bundle discovery data
3. **Use `ChainResolver`** — Try local/bundle first, HTTP as fallback

```python
from schemapin.resolver import ChainResolver, TrustBundleResolver, WellKnownResolver

resolver = ChainResolver([
    TrustBundleResolver.from_json(bundle_json),  # Fast: in-memory
    WellKnownResolver(timeout=5),                  # Slow: HTTP fallback
])
```

---

## Getting Help

- **Technical Specification:** [TECHNICAL_SPECIFICATION.md](../TECHNICAL_SPECIFICATION.md)
- **GitHub Issues:** [github.com/ThirdKeyAI/SchemaPin/issues](https://github.com/ThirdKeyAI/SchemaPin/issues)
- **Website:** [schemapin.org](https://schemapin.org)
- **Verify your deployment:** [schemapin.org/verify.html](https://schemapin.org/verify.html)
