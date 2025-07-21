//! Cryptographic operations for SchemaPin using RSA.

use base64::{engine::general_purpose, Engine as _};
use rand::rngs::OsRng;
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey},
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    pss::{BlindedSigningKey, VerifyingKey},
    signature::{RandomizedSigner, SignatureEncoding, Verifier},
    RsaPrivateKey, RsaPublicKey,
};
use sha2::{Digest, Sha256};
use std::error::Error as StdError;
use std::fmt;

/// Custom error type for cryptographic operations
#[derive(Debug)]
pub enum Error {
    /// RSA key generation or operation error
    Rsa(rsa::Error),
    /// PKCS#1 encoding/decoding error
    Pkcs1(rsa::pkcs1::Error),
    /// PKCS#8 encoding/decoding error
    Pkcs8(rsa::pkcs8::Error),
    /// Base64 encoding/decoding error
    Base64(base64::DecodeError),
    /// Signature verification error
    Signature(rsa::signature::Error),
    /// Invalid key format
    InvalidKeyFormat,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Rsa(e) => write!(f, "RSA error: {}", e),
            Error::Pkcs1(e) => write!(f, "PKCS#1 error: {}", e),
            Error::Pkcs8(e) => write!(f, "PKCS#8 error: {}", e),
            Error::Base64(e) => write!(f, "Base64 error: {}", e),
            Error::Signature(e) => write!(f, "Signature error: {}", e),
            Error::InvalidKeyFormat => write!(f, "Invalid key format"),
        }
    }
}

impl StdError for Error {}

impl From<rsa::Error> for Error {
    fn from(err: rsa::Error) -> Self {
        Error::Rsa(err)
    }
}

impl From<rsa::pkcs1::Error> for Error {
    fn from(err: rsa::pkcs1::Error) -> Self {
        Error::Pkcs1(err)
    }
}

impl From<rsa::pkcs8::Error> for Error {
    fn from(err: rsa::pkcs8::Error) -> Self {
        Error::Pkcs8(err)
    }
}

impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Self {
        Error::Base64(err)
    }
}

impl From<rsa::signature::Error> for Error {
    fn from(err: rsa::signature::Error) -> Self {
        Error::Signature(err)
    }
}

/// Key pair containing private and public keys in PEM format
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub private_key_pem: String,
    pub public_key_pem: String,
}

/// Generate a new RSA key pair and return the private and public keys in PEM format.
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
    
    // Generate a 2048-bit RSA key pair
    let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
    let public_key = private_key.to_public_key();

    // Export to PEM format using PKCS#8
    let private_key_pem = private_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|_| Error::InvalidKeyFormat)?
        .to_string();
    
    let public_key_pem = public_key.to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|_| Error::InvalidKeyFormat)?;

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
    // Try PKCS#8 format first, then fall back to PKCS#1
    let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(private_key_pem))
        .map_err(|_| Error::InvalidKeyFormat)?;

    let mut rng = OsRng;
    let signing_key = BlindedSigningKey::<Sha256>::new(private_key);
    
    // Sign the data using PSS with SHA-256
    let signature = signing_key.sign_with_rng(&mut rng, data);
    
    // Encode signature as base64
    Ok(general_purpose::STANDARD.encode(signature.to_bytes()))
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
    // Try PKCS#8 format first, then fall back to PKCS#1
    let public_key = RsaPublicKey::from_public_key_pem(public_key_pem)
        .or_else(|_| RsaPublicKey::from_pkcs1_pem(public_key_pem))
        .map_err(|_| Error::InvalidKeyFormat)?;

    let verifying_key = VerifyingKey::<Sha256>::new(public_key);
    
    // Decode the base64 signature
    let signature_bytes = general_purpose::STANDARD.decode(signature)?;
    
    // Create signature object
    let signature_obj = rsa::pss::Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| Error::InvalidKeyFormat)?;
    
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
/// SHA-256 hash of the public key as a hexadecimal string.
///
/// # Errors
///
/// Returns an error if the public key format is invalid.
pub fn calculate_key_id(public_key_pem: &str) -> Result<String, Error> {
    // Try PKCS#8 format first, then fall back to PKCS#1
    let public_key = RsaPublicKey::from_public_key_pem(public_key_pem)
        .or_else(|_| RsaPublicKey::from_pkcs1_pem(public_key_pem))
        .map_err(|_| Error::InvalidKeyFormat)?;

    // Convert to DER format for consistent hashing
    let der_bytes = public_key.to_public_key_der()
        .map_err(|_| Error::InvalidKeyFormat)?;
    
    // Calculate SHA-256 hash
    let mut hasher = Sha256::new();
    hasher.update(der_bytes.as_bytes());
    let hash = hasher.finalize();
    
    Ok(hex::encode(hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key_pair() {
        let key_pair = generate_key_pair().unwrap();
        assert!(key_pair.private_key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(key_pair.public_key_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
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
        let is_invalid = verify_signature(&key_pair.public_key_pem, wrong_data, &signature).unwrap();
        assert!(!is_invalid);
    }

    #[test]
    fn test_calculate_key_id() {
        let key_pair = generate_key_pair().unwrap();
        let key_id = calculate_key_id(&key_pair.public_key_pem).unwrap();
        
        // SHA-256 hash should be 64 characters long (32 bytes in hex)
        assert_eq!(key_id.len(), 64);
        
        // Should be deterministic
        let key_id2 = calculate_key_id(&key_pair.public_key_pem).unwrap();
        assert_eq!(key_id, key_id2);
    }
}