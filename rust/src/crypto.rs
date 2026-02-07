//! Cryptographic operations for SchemaPin using ECDSA P-256.

use base64::{engine::general_purpose, Engine as _};
use p256::{
    ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey},
    pkcs8::{spki, DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    PublicKey, SecretKey,
};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::error::Error as StdError;
use std::fmt;

/// Custom error type for cryptographic operations
#[derive(Debug)]
pub enum Error {
    /// ECDSA key generation or operation error
    Ecdsa(String),
    /// PKCS#8 encoding/decoding error
    Pkcs8(p256::pkcs8::Error),
    /// SPKI encoding/decoding error
    Spki(spki::Error),
    /// Base64 encoding/decoding error
    Base64(base64::DecodeError),
    /// Signature verification error
    Signature(String),
    /// Invalid key format
    InvalidKeyFormat,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Ecdsa(e) => write!(f, "ECDSA error: {}", e),
            Error::Pkcs8(e) => write!(f, "PKCS#8 error: {}", e),
            Error::Spki(e) => write!(f, "SPKI error: {}", e),
            Error::Base64(e) => write!(f, "Base64 error: {}", e),
            Error::Signature(e) => write!(f, "Signature error: {}", e),
            Error::InvalidKeyFormat => write!(f, "Invalid key format"),
        }
    }
}

impl StdError for Error {}

impl From<p256::pkcs8::Error> for Error {
    fn from(err: p256::pkcs8::Error) -> Self {
        Error::Pkcs8(err)
    }
}

impl From<spki::Error> for Error {
    fn from(err: spki::Error) -> Self {
        Error::Spki(err)
    }
}

impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Self {
        Error::Base64(err)
    }
}

/// Key pair containing private and public keys in PEM format
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub private_key_pem: String,
    pub public_key_pem: String,
}

/// Generate a new ECDSA P-256 key pair and return the private and public keys in PEM format.
///
/// # Returns
///
/// A `KeyPair` struct containing both private and public keys in PEM format.
///
/// # Errors
///
/// Returns an error if key generation fails.
pub fn generate_key_pair() -> Result<KeyPair, Error> {
    let mut rng = OsRng;

    // Generate a P-256 (secp256r1) ECDSA key pair
    let secret_key = SecretKey::random(&mut rng);
    let public_key = secret_key.public_key();

    // Export to PEM format using PKCS#8
    let private_key_pem = secret_key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)?
        .to_string();

    let public_key_pem = public_key.to_public_key_pem(p256::pkcs8::LineEnding::LF)?;

    Ok(KeyPair {
        private_key_pem,
        public_key_pem,
    })
}

/// Sign the given data using the private key and return the base64-encoded signature.
///
/// # Arguments
///
/// * `private_key_pem` - The private key in PEM format
/// * `data` - The data to sign
///
/// # Returns
///
/// Base64-encoded signature string.
///
/// # Errors
///
/// Returns an error if the private key is invalid or signing fails.
pub fn sign_data(private_key_pem: &str, data: &[u8]) -> Result<String, Error> {
    // Load the private key from PEM
    let secret_key = SecretKey::from_pkcs8_pem(private_key_pem)?;
    let signing_key = SigningKey::from(secret_key);

    // Sign the data using ECDSA with SHA-256
    let signature: p256::ecdsa::Signature = signing_key.sign(data);

    // Encode signature as base64
    Ok(general_purpose::STANDARD.encode(signature.to_der()))
}

/// Verify the signature of the given data using the public key.
///
/// # Arguments
///
/// * `public_key_pem` - The public key in PEM format
/// * `data` - The original data that was signed
/// * `signature` - The base64-encoded signature to verify
///
/// # Returns
///
/// `true` if the signature is valid, `false` otherwise.
///
/// # Errors
///
/// Returns an error if the public key is invalid or signature format is invalid.
pub fn verify_signature(public_key_pem: &str, data: &[u8], signature: &str) -> Result<bool, Error> {
    // Load the public key from PEM
    let public_key = PublicKey::from_public_key_pem(public_key_pem)?;
    let verifying_key = VerifyingKey::from(public_key);

    // Decode the base64 signature
    let signature_bytes = general_purpose::STANDARD.decode(signature)?;

    // Create signature object from DER bytes
    let signature_obj =
        Signature::from_der(&signature_bytes).map_err(|_| Error::InvalidKeyFormat)?;

    // Verify the signature
    match verifying_key.verify(data, &signature_obj) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Calculate the SHA-256 hash of the public key to be used as the key ID.
///
/// # Arguments
///
/// * `public_key_pem` - The public key in PEM format
///
/// # Returns
///
/// SHA-256 hash of the public key as a hexadecimal string prefixed with "sha256:".
///
/// # Errors
///
/// Returns an error if the public key format is invalid.
pub fn calculate_key_id(public_key_pem: &str) -> Result<String, Error> {
    // Load the public key from PEM
    let public_key = PublicKey::from_public_key_pem(public_key_pem)?;

    // Convert to DER format for consistent hashing
    let der_bytes = public_key.to_public_key_der()?;

    // Calculate SHA-256 hash
    let mut hasher = Sha256::new();
    hasher.update(der_bytes.as_bytes());
    let hash = hasher.finalize();

    Ok(format!("sha256:{}", hex::encode(hash)))
}

/// Key manager for ECDSA P-256 operations (matches Python API)
pub struct KeyManager;

impl KeyManager {
    /// Generate new ECDSA P-256 key pair.
    pub fn generate_keypair() -> Result<(SecretKey, PublicKey), Error> {
        let mut rng = OsRng;
        let secret_key = SecretKey::random(&mut rng);
        let public_key = secret_key.public_key();
        Ok((secret_key, public_key))
    }

    /// Export private key to PEM format.
    pub fn export_private_key_pem(private_key: &SecretKey) -> Result<String, Error> {
        Ok(private_key
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)?
            .to_string())
    }

    /// Export public key to PEM format.
    pub fn export_public_key_pem(public_key: &PublicKey) -> Result<String, Error> {
        Ok(public_key.to_public_key_pem(p256::pkcs8::LineEnding::LF)?)
    }

    /// Load private key from PEM format.
    pub fn load_private_key_pem(pem_data: &str) -> Result<SecretKey, Error> {
        Ok(SecretKey::from_pkcs8_pem(pem_data)?)
    }

    /// Load public key from PEM format.
    pub fn load_public_key_pem(pem_data: &str) -> Result<PublicKey, Error> {
        Ok(PublicKey::from_public_key_pem(pem_data)?)
    }

    /// Calculate SHA-256 fingerprint of public key.
    pub fn calculate_key_fingerprint(public_key: &PublicKey) -> Result<String, Error> {
        let der_bytes = public_key.to_public_key_der()?;
        let mut hasher = Sha256::new();
        hasher.update(der_bytes.as_bytes());
        let hash = hasher.finalize();
        Ok(format!("sha256:{}", hex::encode(hash)))
    }

    /// Calculate SHA-256 fingerprint from PEM-encoded public key.
    pub fn calculate_key_fingerprint_from_pem(public_key_pem: &str) -> Result<String, Error> {
        let public_key = Self::load_public_key_pem(public_key_pem)?;
        Self::calculate_key_fingerprint(&public_key)
    }
}

/// Signature manager for ECDSA operations (matches Python API)
pub struct SignatureManager;

impl SignatureManager {
    /// Sign hash using ECDSA P-256 and return Base64-encoded signature.
    pub fn sign_hash(hash_bytes: &[u8], private_key: &SecretKey) -> Result<String, Error> {
        let signing_key = SigningKey::from(private_key.clone());
        let signature: p256::ecdsa::Signature = signing_key.sign(hash_bytes);
        Ok(general_purpose::STANDARD.encode(signature.to_der()))
    }

    /// Verify ECDSA signature against hash.
    pub fn verify_signature(
        hash_bytes: &[u8],
        signature_b64: &str,
        public_key: &PublicKey,
    ) -> Result<bool, Error> {
        let verifying_key = VerifyingKey::from(*public_key);
        let signature_bytes = general_purpose::STANDARD.decode(signature_b64)?;
        let signature_obj =
            Signature::from_der(&signature_bytes).map_err(|_| Error::InvalidKeyFormat)?;

        match verifying_key.verify(hash_bytes, &signature_obj) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Sign schema hash and return Base64 signature.
    pub fn sign_schema_hash(schema_hash: &[u8], private_key: &SecretKey) -> Result<String, Error> {
        Self::sign_hash(schema_hash, private_key)
    }

    /// Verify schema signature against hash.
    pub fn verify_schema_signature(
        schema_hash: &[u8],
        signature_b64: &str,
        public_key: &PublicKey,
    ) -> Result<bool, Error> {
        Self::verify_signature(schema_hash, signature_b64, public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key_pair() {
        let key_pair = generate_key_pair().unwrap();
        assert!(key_pair
            .private_key_pem
            .starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(key_pair
            .public_key_pem
            .starts_with("-----BEGIN PUBLIC KEY-----"));
    }

    #[test]
    fn test_sign_and_verify() {
        let key_pair = generate_key_pair().unwrap();
        let data = b"Hello, World!";

        let signature = sign_data(&key_pair.private_key_pem, data).unwrap();
        let is_valid = verify_signature(&key_pair.public_key_pem, data, &signature).unwrap();

        assert!(is_valid);

        // Test with wrong data
        let wrong_data = b"Wrong data";
        let is_invalid =
            verify_signature(&key_pair.public_key_pem, wrong_data, &signature).unwrap();
        assert!(!is_invalid);
    }

    #[test]
    fn test_calculate_key_id() {
        let key_pair = generate_key_pair().unwrap();
        let key_id = calculate_key_id(&key_pair.public_key_pem).unwrap();

        // Should start with "sha256:" and be 71 characters total (7 + 64)
        assert!(key_id.starts_with("sha256:"));
        assert_eq!(key_id.len(), 71);

        // Should be deterministic
        let key_id2 = calculate_key_id(&key_pair.public_key_pem).unwrap();
        assert_eq!(key_id, key_id2);
    }

    #[test]
    fn test_key_manager_api() {
        let (private_key, public_key) = KeyManager::generate_keypair().unwrap();
        let private_key_pem = KeyManager::export_private_key_pem(&private_key).unwrap();
        let public_key_pem = KeyManager::export_public_key_pem(&public_key).unwrap();

        let loaded_private = KeyManager::load_private_key_pem(&private_key_pem).unwrap();
        let loaded_public = KeyManager::load_public_key_pem(&public_key_pem).unwrap();

        // Keys should be equivalent
        assert_eq!(private_key.to_bytes(), loaded_private.to_bytes());
        // Test that the public keys can be used to verify the same signature
        let test_data = b"test data";
        let sig1 = SignatureManager::sign_hash(test_data, &private_key).unwrap();
        assert!(SignatureManager::verify_signature(test_data, &sig1, &public_key).unwrap());
        assert!(SignatureManager::verify_signature(test_data, &sig1, &loaded_public).unwrap());
    }

    #[test]
    fn test_signature_manager_api() {
        let (private_key, public_key) = KeyManager::generate_keypair().unwrap();
        let data = b"Test data for signature";

        let signature = SignatureManager::sign_hash(data, &private_key).unwrap();
        let is_valid = SignatureManager::verify_signature(data, &signature, &public_key).unwrap();

        assert!(is_valid);
    }
}
