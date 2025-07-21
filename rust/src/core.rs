use serde::{Deserialize, Serialize};

/// Information about a public key used for verification
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PublicKeyInfo {
    /// Type of the cryptographic key (e.g., "ECDSA_P256")
    pub key_type: String,
    /// Unique identifier for the key
    pub key_id: String,
    /// PEM-encoded public key
    pub public_key_pem: String,
    /// Optional URL for key revocation information
    pub revocation_info_url: Option<String>,
}

/// Information about a cryptographic signature
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SignatureInfo {
    /// Identifier of the key used to create this signature
    pub key_id: String,
    /// Base64-encoded signature
    pub signature: String,
    /// ISO 8601 timestamp when the signature was created
    pub signed_at: String,
}

/// Information about when and how a schema was pinned
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PinningInfo {
    /// SHA-256 hash of the schema content
    pub schema_hash: String,
    /// ISO 8601 timestamp when the schema was pinned
    pub pinned_at: String,
    /// Optional ISO 8601 timestamp when the pinning expires
    pub expires_at: Option<String>,
}

/// A complete SchemaPin containing schema, pinning info, and signatures
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SchemaPin {
    /// URI identifying the schema
    pub schema_uri: String,
    /// The actual schema content as JSON string
    pub schema_content: String,
    /// Information about when and how this schema was pinned
    pub pinning_info: PinningInfo,
    /// List of cryptographic signatures for this schema
    pub signatures: Vec<SignatureInfo>,
}