# SchemaPin - Rust Implementation

Cryptographic schema integrity verification for AI tools - Rust implementation using ECDSA P-256.

## Overview

SchemaPin provides a robust framework for verifying the integrity and authenticity of JSON schemas used by AI tools and services. This Rust implementation uses ECDSA P-256 cryptographic signatures to ensure that schemas haven't been tampered with and come from trusted sources.

This implementation is fully compatible with the Python, JavaScript, and Go implementations, using the same cryptographic standards:
- **ECDSA with P-256 curve (secp256r1)** for signatures
- **SHA-256** for hashing
- **PKCS#8 PEM format** for key serialization

## Features

- **ECDSA P-256 Key Generation**: Generate ECDSA P-256 key pairs for signing and verification
- **Digital Signatures**: Sign data using ECDSA with SHA-256
- **Signature Verification**: Verify signatures to ensure data integrity
- **Key ID Calculation**: Generate SHA-256 fingerprints for key identification
- **PEM Format Support**: Full support for PKCS#8 key formats
- **Schema Canonicalization**: Deterministic JSON serialization for consistent hashing
- **Trust Bundles**: Offline verification with pre-shared discovery documents
- **Resolver Abstraction**: Pluggable discovery via local files, trust bundles, or HTTP
- **TOFU Key Pinning**: Trust-on-first-use key pinning per tool+domain
- **Revocation Checking**: Combined simple list and standalone document revocation
- **Cross-Language Compatibility**: Compatible with Python, JavaScript, and Go implementations

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
schemapin = "1.2.0"
```

To enable HTTP-based discovery (requires async runtime):

```toml
[dependencies]
schemapin = { version = "1.2.0", features = ["fetch"] }
```

## Feature Flags

| Feature | Description |
|---------|-------------|
| `default` | Everything except HTTP (all types, canonicalize, pinning, resolvers, offline verification) |
| `fetch` | Adds `WellKnownResolver`, `AsyncSchemaResolver`, `fetch_well_known()`, `verify_schema()`. Brings in `reqwest`, `tokio`, `async-trait`. |

## Quick Start

### Signing and Verifying Raw Data

```rust
use schemapin::crypto::{generate_key_pair, sign_data, verify_signature, calculate_key_id};

// Generate a new key pair
let key_pair = generate_key_pair().unwrap();

// Sign some data
let data = b"Hello, World!";
let signature = sign_data(&key_pair.private_key_pem, data).unwrap();

// Verify the signature
let is_valid = verify_signature(&key_pair.public_key_pem, data, &signature).unwrap();
assert!(is_valid);

// Calculate key ID
let key_id = calculate_key_id(&key_pair.public_key_pem).unwrap();
println!("Key ID: {}", key_id);
```

### Offline Schema Verification

```rust,no_run
use schemapin::canonicalize::canonicalize_and_hash;
use schemapin::crypto::{generate_key_pair, sign_data};
use schemapin::discovery::build_well_known_response;
use schemapin::pinning::KeyPinStore;
use schemapin::verification::verify_schema_offline;
use serde_json::json;

// Developer: sign a schema
let key_pair = generate_key_pair().unwrap();
let schema = json!({"name": "my_tool", "description": "A useful tool"});
let hash = canonicalize_and_hash(&schema);
let signature = sign_data(&key_pair.private_key_pem, &hash).unwrap();

// Build discovery response
let discovery = build_well_known_response(
    &key_pair.public_key_pem, Some("My Corp"), vec![], "1.2",
);

// Client: verify the schema offline
let mut pin_store = KeyPinStore::new();
let result = verify_schema_offline(
    &schema, &signature, "example.com", "my_tool",
    &discovery, None, &mut pin_store,
);
assert!(result.valid);
```

### Using Trust Bundles

```rust,no_run
use schemapin::resolver::TrustBundleResolver;
use schemapin::verification::verify_schema_with_resolver;
use schemapin::pinning::KeyPinStore;

// Load a trust bundle from JSON
let bundle_json = std::fs::read_to_string("trust-bundle.json").unwrap();
let resolver = TrustBundleResolver::from_json(&bundle_json).unwrap();

// Verify using the resolver
let mut pin_store = KeyPinStore::new();
let schema = serde_json::json!({"name": "my_tool"});
let result = verify_schema_with_resolver(
    &schema, "base64-signature", "example.com", "my_tool",
    &resolver, &mut pin_store,
);
```

## Building and Testing

```bash
# Build (no HTTP dependencies)
cargo build

# Build with HTTP support
cargo build --features fetch

# Run tests
cargo test

# Run tests with all features
cargo test --all-features

# Check code quality
cargo clippy
cargo clippy --all-features

# Format code
cargo fmt
```

## Security

This implementation uses:
- **ECDSA with P-256 curve (secp256r1)** for signatures
- **SHA-256** for hashing and signature algorithms
- **Secure random number generation** via `OsRng`
- **Constant-time operations** where possible

The cryptographic operations are provided by the `p256` crate, which implements the ECDSA algorithm according to industry standards.

## Cross-Language Compatibility

This Rust implementation is designed to be fully compatible with other SchemaPin implementations:

- **Identical signature format**: Base64-encoded ECDSA signatures
- **Compatible key formats**: PKCS#8 PEM encoding
- **Same fingerprint calculation**: SHA-256 hash of DER-encoded public keys
- **Interoperable signatures**: Can verify signatures from Python/JavaScript/Go implementations

## Error Handling

The crate provides two error types:

- **`crypto::Error`**: Low-level cryptographic errors (`Ecdsa`, `Pkcs8`, `Base64`, `Signature`, `InvalidKeyFormat`)
- **`error::Error`**: Unified error type for the full verification workflow, wrapping `crypto::Error` and adding `Discovery`, `Revocation`, `Verification`, `Json`, `Io`, and feature-gated `Http` variants

## Dependencies

- `p256`: ECDSA P-256 cryptographic operations
- `rand`: Secure random number generation
- `sha2`: SHA-256 hashing
- `base64`: Base64 encoding/decoding
- `hex`: Hexadecimal encoding
- `serde`, `serde_json`: Serialization support
- `thiserror`: Error derive macros
- `chrono`: Timestamp handling
- `reqwest` (optional, `fetch`): HTTP client
- `tokio` (optional, `fetch`): Async runtime
- `async-trait` (optional, `fetch`): Async trait support

## License

MIT License - see the main project LICENSE file for details.
