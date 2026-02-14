//! # SchemaPin - Rust Implementation
//!
//! Cryptographic schema integrity verification for AI tools.
//!
//! SchemaPin provides a robust framework for verifying the integrity and authenticity
//! of JSON schemas used by AI tools and services. It uses ECDSA P-256 cryptographic signatures
//! to ensure that schemas haven't been tampered with and come from trusted sources.
//!
//! ## Features
//!
//! - **ECDSA P-256 Key Generation**: Generate ECDSA P-256 key pairs for signing and verification
//! - **Digital Signatures**: Sign data using ECDSA with SHA-256
//! - **Signature Verification**: Verify signatures to ensure data integrity
//! - **Key ID Calculation**: Generate SHA-256 fingerprints for key identification
//! - **PEM Format Support**: Full support for PKCS#8 key formats
//! - **Schema Canonicalization**: Deterministic JSON serialization for consistent hashing
//! - **Trust Bundles**: Offline verification with pre-shared discovery documents
//! - **Resolver Abstraction**: Pluggable discovery via local files, trust bundles, or HTTP
//! - **TOFU Key Pinning**: Trust-on-first-use key pinning per tool+domain
//! - **Revocation Checking**: Combined simple list and standalone document revocation
//!
//! ## Feature Flags
//!
//! - `fetch` — Enables HTTP-based discovery (`WellKnownResolver`, `AsyncSchemaResolver`,
//!   `fetch_well_known`, `fetch_revocation_document`, `verify_schema`). Brings in
//!   `reqwest`, `tokio`, and `async-trait`.
//!
//! ## Quick Start
//!
//! ```rust
//! use schemapin::crypto::{generate_key_pair, sign_data, verify_signature, calculate_key_id};
//!
//! // Generate a new key pair
//! let key_pair = generate_key_pair().unwrap();
//!
//! // Sign some data
//! let data = b"Hello, World!";
//! let signature = sign_data(&key_pair.private_key_pem, data).unwrap();
//!
//! // Verify the signature
//! let is_valid = verify_signature(&key_pair.public_key_pem, data, &signature).unwrap();
//! assert!(is_valid);
//!
//! // Calculate key ID
//! let key_id = calculate_key_id(&key_pair.public_key_pem).unwrap();
//! println!("Key ID: {}", key_id);
//! ```
//!
//! ## Security
//!
//! This implementation uses:
//! - ECDSA with P-256 curve (secp256r1) for signatures
//! - SHA-256 for hashing and signature algorithms
//! - Secure random number generation
//! - Constant-time operations where possible
//!
//! ## Error Handling
//!
//! All cryptographic operations return `Result<T, Error>` types for proper error handling.
//! The [`crypto::Error`] enum provides detailed error information for debugging.
//! The [`error::Error`] enum provides a unified error type for the full verification workflow.

// Preserved modules (backward compatible)
pub mod core;
pub mod crypto;

// New modules (v1.2.0)
pub mod canonicalize;
pub mod discovery;
pub mod error;
pub mod pinning;
pub mod resolver;
pub mod revocation;
pub mod skill;
pub mod types;
pub mod verification;
