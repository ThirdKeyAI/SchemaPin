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
- **Cross-Language Compatibility**: Compatible with Python, JavaScript, and Go implementations

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
schemapin = "1.1.4"
```

Or install from git:

```bash
cargo add --git https://github.com/thirdkey/schemapin schemapin
```

## Quick Start

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

## Advanced Usage

### Using the High-Level API

```rust
use schemapin::crypto::{KeyManager, SignatureManager};

// Generate keys using the manager
let (private_key, public_key) = KeyManager::generate_keypair().unwrap();
let private_key_pem = KeyManager::export_private_key_pem(&private_key).unwrap();
let public_key_pem = KeyManager::export_public_key_pem(&public_key).unwrap();

// Sign and verify using the manager
let data = b"Schema data to sign";
let signature = SignatureManager::sign_hash(data, &private_key).unwrap();
let is_valid = SignatureManager::verify_signature(data, &signature, &public_key).unwrap();
assert!(is_valid);
```

## Building and Testing

```bash
# Build the project
cargo build

# Run tests
cargo test

# Run with optimizations
cargo build --release

# Check code quality
cargo clippy

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

All cryptographic operations return `Result<T, Error>` types for proper error handling. The `Error` enum provides detailed error information:

- `Ecdsa`: ECDSA key generation or operation errors
- `Pkcs8`: PKCS#8 encoding/decoding errors
- `Base64`: Base64 encoding/decoding errors
- `Signature`: Signature verification errors
- `InvalidKeyFormat`: Invalid key format errors

## Dependencies

- `p256`: ECDSA P-256 cryptographic operations
- `rand`: Secure random number generation
- `sha2`: SHA-256 hashing
- `base64`: Base64 encoding/decoding
- `hex`: Hexadecimal encoding
- `serde`: Serialization support

## License

MIT License - see the main project LICENSE file for details.