use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("PKCS8 error: {0}")]
    Pkcs8(String),

    #[error("SPKI error: {0}")]
    Spki(String),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Invalid key format")]
    InvalidKeyFormat,

    #[error("Discovery error: {0}")]
    Discovery(String),

    #[error("Revocation error: {0}")]
    Revocation(String),

    #[error("Verification failed: {code}: {message}")]
    Verification { code: ErrorCode, message: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[cfg(feature = "fetch")]
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
}

impl From<crate::crypto::Error> for Error {
    fn from(err: crate::crypto::Error) -> Self {
        match err {
            crate::crypto::Error::Pkcs8(e) => Error::Pkcs8(e.to_string()),
            crate::crypto::Error::Spki(e) => Error::Spki(e.to_string()),
            crate::crypto::Error::Base64(e) => Error::Base64(e),
            crate::crypto::Error::Ecdsa(msg) => Error::Crypto(msg),
            crate::crypto::Error::Signature(msg) => Error::Crypto(msg),
            crate::crypto::Error::InvalidKeyFormat => Error::InvalidKeyFormat,
        }
    }
}

impl From<p256::pkcs8::Error> for Error {
    fn from(err: p256::pkcs8::Error) -> Self {
        Error::Pkcs8(err.to_string())
    }
}

impl From<p256::pkcs8::spki::Error> for Error {
    fn from(err: p256::pkcs8::spki::Error) -> Self {
        Error::Spki(err.to_string())
    }
}

/// Error codes for structured verification results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ErrorCode {
    #[serde(rename = "SIGNATURE_INVALID")]
    SignatureInvalid,
    #[serde(rename = "KEY_NOT_FOUND")]
    KeyNotFound,
    #[serde(rename = "KEY_REVOKED")]
    KeyRevoked,
    #[serde(rename = "KEY_PIN_MISMATCH")]
    KeyPinMismatch,
    #[serde(rename = "DISCOVERY_FETCH_FAILED")]
    DiscoveryFetchFailed,
    #[serde(rename = "DISCOVERY_INVALID")]
    DiscoveryInvalid,
    #[serde(rename = "DOMAIN_MISMATCH")]
    DomainMismatch,
    #[serde(rename = "SCHEMA_CANONICALIZATION_FAILED")]
    SchemaCanonicalizationFailed,
    /// (v1.4) Signature declared a `canonicalization` algorithm identifier that
    /// this verifier does not support. Hard failure — verifiers MUST reject
    /// unknown algorithms rather than silently fall back.
    #[serde(rename = "CANONICALIZATION_UNSUPPORTED")]
    CanonicalizationUnsupported,
    /// (v1.4) A2A scope violation — the tool provider's domain is not in the
    /// caller's `AllowedDomains` allow-list (under the AgentPin
    /// empty-list-equals-unrestricted convention).
    #[serde(rename = "A2A_SCOPE_VIOLATION")]
    A2aScopeViolation,
    /// (v1.4) A trust bundle was passed to `verify_trust_bundle` without a
    /// `bundle_authority` / `signature` pair. Bundle distribution requires a
    /// signed bundle.
    #[serde(rename = "BUNDLE_UNSIGNED")]
    BundleUnsigned,
    /// (v1.4) A signed trust bundle's `expires_at` is in the past.
    #[serde(rename = "BUNDLE_EXPIRED")]
    BundleExpired,
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ErrorCode::SignatureInvalid => "SIGNATURE_INVALID",
            ErrorCode::KeyNotFound => "KEY_NOT_FOUND",
            ErrorCode::KeyRevoked => "KEY_REVOKED",
            ErrorCode::KeyPinMismatch => "KEY_PIN_MISMATCH",
            ErrorCode::DiscoveryFetchFailed => "DISCOVERY_FETCH_FAILED",
            ErrorCode::DiscoveryInvalid => "DISCOVERY_INVALID",
            ErrorCode::DomainMismatch => "DOMAIN_MISMATCH",
            ErrorCode::SchemaCanonicalizationFailed => "SCHEMA_CANONICALIZATION_FAILED",
            ErrorCode::CanonicalizationUnsupported => "CANONICALIZATION_UNSUPPORTED",
            ErrorCode::A2aScopeViolation => "A2A_SCOPE_VIOLATION",
            ErrorCode::BundleUnsigned => "BUNDLE_UNSIGNED",
            ErrorCode::BundleExpired => "BUNDLE_EXPIRED",
        };
        write!(f, "{}", s)
    }
}
