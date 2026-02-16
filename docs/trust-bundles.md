# Trust Bundles and Offline Verification

SchemaPin v1.2 introduced trust bundles and pluggable discovery resolvers for environments where HTTP-based `.well-known` discovery is unavailable or impractical.

---

## When to Use Offline Verification

- **Air-gapped networks** — No internet access
- **CI/CD pipelines** — Deterministic builds without HTTP calls
- **Embedded systems** — Pre-provisioned trust data
- **Enterprise deployments** — Centralized trust management
- **High-throughput** — Avoid per-verification network latency

---

## Trust Bundles

A trust bundle packages discovery documents and revocation data together in a single JSON file.

### Bundle Format

```json
{
  "schemapin_version": "1.2",
  "bundle_id": "enterprise-tools-2026-02",
  "created_at": "2026-02-15T00:00:00Z",
  "entries": [
    {
      "domain": "example.com",
      "discovery": {
        "schema_version": "1.3",
        "developer_name": "Example Corp",
        "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
        "revoked_keys": [],
        "revocation_endpoint": "https://example.com/.well-known/schemapin-revocations.json"
      },
      "revocation": {
        "revoked_keys": [],
        "revoked_schemas": []
      }
    },
    {
      "domain": "partner.com",
      "discovery": { "..." : "..." },
      "revocation": null
    }
  ]
}
```

### Creating a Trust Bundle

#### Python

```python
from schemapin.bundle import SchemaPinTrustBundle

# Build from individual documents
bundle = SchemaPinTrustBundle()
bundle.add_entry("example.com", discovery_doc, revocation_doc)
bundle.add_entry("partner.com", partner_discovery, None)

# Serialize to JSON
bundle_json = bundle.to_json()

# Save to file
with open("trust-bundle.json", "w") as f:
    f.write(bundle_json)
```

#### JavaScript

```javascript
import { SchemaPinTrustBundle } from 'schemapin';

const bundle = new SchemaPinTrustBundle();
bundle.addEntry('example.com', discoveryDoc, revocationDoc);
bundle.addEntry('partner.com', partnerDiscovery, null);

const bundleJson = bundle.toJson();
```

### Loading a Trust Bundle

#### Python

```python
from schemapin.bundle import SchemaPinTrustBundle

bundle = SchemaPinTrustBundle.from_json(open("trust-bundle.json").read())

# Look up a domain
discovery = bundle.find_discovery("example.com")
revocation = bundle.find_revocation("example.com")

if discovery:
    print(f"Found: {discovery['developer_name']}")
```

#### JavaScript

```javascript
import { SchemaPinTrustBundle } from 'schemapin';

const bundle = SchemaPinTrustBundle.fromJson(bundleJson);
const discovery = bundle.findDiscovery('example.com');
const revocation = bundle.findRevocation('example.com');
```

---

## Offline Verification

Verify a schema signature without any HTTP calls by providing the discovery data directly:

### Python

```python
from schemapin.verification import verify_schema_offline, KeyPinStore

pin_store = KeyPinStore()

result = verify_schema_offline(
    schema=tool_schema,
    signature_b64=signature,
    domain="example.com",
    tool_id="calculate_sum",
    discovery_data=discovery_doc,
    revocation_doc=revocation_doc,
    pin_store=pin_store,
)

if result["valid"]:
    print("Schema verified offline")
```

### JavaScript

```javascript
import { verifySchemaOffline, KeyPinStore } from 'schemapin';

const result = verifySchemaOffline(
    schema, signatureB64, 'example.com', 'calculate_sum',
    discoveryData, revocationDoc, new KeyPinStore(),
);
```

### Go

```go
result := verification.VerifySchemaOffline(
    schema, signatureB64, "example.com", "calculate_sum",
    discoveryData, revocationDoc, pinStore,
)
```

### Rust

```rust
let result = verify_schema_offline(
    &schema, &signature_b64, "example.com", "calculate_sum",
    &discovery_data, revocation_doc.as_ref(), Some(&pin_store),
);
```

---

## Pluggable Discovery Resolvers

SchemaPin v1.2 introduces a resolver abstraction. Resolvers implement discovery document retrieval from different sources.

### Available Resolvers

| Resolver | Source | Use Case |
|----------|--------|----------|
| `WellKnownResolver` | HTTP `.well-known` | Standard online discovery |
| `LocalFileResolver` | Local filesystem | Development, CI/CD |
| `TrustBundleResolver` | In-memory bundle | Air-gapped, enterprise |
| `ChainResolver` | Multiple resolvers | Fallback chains |

### WellKnownResolver

Fetches discovery documents from `/.well-known/schemapin.json` over HTTPS:

```python
from schemapin.resolver import WellKnownResolver

resolver = WellKnownResolver(timeout=10)
discovery = resolver.resolve("example.com")
```

### LocalFileResolver

Reads discovery documents from a local directory:

```python
from schemapin.resolver import LocalFileResolver

# Files named: {domain}.json (e.g., example.com.json)
resolver = LocalFileResolver("/path/to/discovery-docs/")
discovery = resolver.resolve("example.com")
# Reads: /path/to/discovery-docs/example.com.json
```

### TrustBundleResolver

Uses an in-memory trust bundle:

```python
from schemapin.resolver import TrustBundleResolver

resolver = TrustBundleResolver.from_json(bundle_json)
discovery = resolver.resolve("example.com")
```

### ChainResolver

Tries resolvers in order, returning the first successful result:

```python
from schemapin.resolver import ChainResolver, TrustBundleResolver, WellKnownResolver

resolver = ChainResolver([
    TrustBundleResolver.from_json(bundle_json),  # Try bundle first
    WellKnownResolver(timeout=10),                # Fall back to HTTP
])
```

---

## Resolver-Based Verification

Combine resolvers with verification for flexible discovery:

### Python

```python
from schemapin.verification import verify_schema_with_resolver
from schemapin.resolver import ChainResolver, TrustBundleResolver, LocalFileResolver

# Chain: bundle → local files → HTTP
resolver = ChainResolver([
    TrustBundleResolver.from_json(bundle_json),
    LocalFileResolver("/etc/schemapin/discovery/"),
])

result = verify_schema_with_resolver(
    schema=tool_schema,
    signature_b64=signature,
    domain="example.com",
    tool_id="calculate_sum",
    resolver=resolver,
    pin_store=pin_store,
)
```

### JavaScript

```javascript
import { verifySchemaWithResolver, ChainResolver, TrustBundleResolver } from 'schemapin';

const resolver = new ChainResolver([
    TrustBundleResolver.fromJson(bundleJson),
]);

const result = verifySchemaWithResolver(
    schema, signatureB64, 'example.com', 'calculate_sum',
    resolver, pinStore,
);
```

### Go

```go
resolver := resolver.NewChainResolver([]resolver.Resolver{
    resolver.NewTrustBundleResolver(bundleJSON),
    resolver.NewWellKnownResolver(10),
})

result := verification.VerifySchemaWithResolver(
    schema, signatureB64, "example.com", "calculate_sum",
    resolver, pinStore,
)
```

### Rust

```rust
let resolver = ChainResolver::new(vec![
    Box::new(TrustBundleResolver::from_json(&bundle_json)?),
    Box::new(WellKnownResolver::new(Duration::from_secs(10))),
]);

let result = verify_schema_with_resolver(
    &schema, &signature_b64, "example.com", "calculate_sum",
    &resolver, Some(&pin_store),
);
```

---

## Standalone Revocation Documents

SchemaPin v1.2 also supports standalone revocation documents:

### Python

```python
from schemapin.revocation import (
    build_revocation_document,
    add_revoked_key,
    check_revocation,
    RevocationReason,
)

# Create a revocation document
doc = build_revocation_document("example.com")

# Revoke a key by fingerprint
add_revoked_key(doc, "sha256:abc123...", RevocationReason.KEY_COMPROMISE)

# Check if a fingerprint is revoked (raises if revoked)
try:
    check_revocation(doc, some_fingerprint)
    print("Key is not revoked")
except Exception as e:
    print(f"Key is revoked: {e}")
```

### Revocation Reasons

| Reason | Description |
|--------|-------------|
| `KEY_COMPROMISE` | Private key was compromised |
| `SUPERSEDED` | Key replaced by a new key |
| `CESSATION_OF_OPERATION` | Key is no longer in use |
| `PRIVILEGE_WITHDRAWN` | Key privileges have been revoked |

---

## Best Practices

1. **Bundle freshness** — Rebuild trust bundles periodically to pick up key rotations and revocations
2. **Chain resolvers** — Use `ChainResolver` with bundle first, HTTP fallback for resilience
3. **Always check revocation** — Even offline, include revocation data in your bundles
4. **Persist pin stores** — TOFU pins work across online and offline verification modes
5. **Version bundles** — Use `bundle_id` to track which version of the bundle is deployed
