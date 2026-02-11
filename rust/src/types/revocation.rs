use serde::{Deserialize, Serialize};

/// Standalone revocation document for a domain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevocationDocument {
    pub schemapin_version: String,
    pub domain: String,
    pub updated_at: String,
    #[serde(default)]
    pub revoked_keys: Vec<RevokedKey>,
}

/// A single revoked key entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevokedKey {
    pub fingerprint: String,
    pub revoked_at: String,
    pub reason: RevocationReason,
}

/// Reason for key revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    KeyCompromise,
    Superseded,
    CessationOfOperation,
    PrivilegeWithdrawn,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation_document_serde_roundtrip() {
        let doc = RevocationDocument {
            schemapin_version: "1.2".to_string(),
            domain: "example.com".to_string(),
            updated_at: "2026-02-10T00:00:00Z".to_string(),
            revoked_keys: vec![RevokedKey {
                fingerprint:
                    "sha256:abc123def456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                        .to_string(),
                revoked_at: "2026-02-10T00:00:00Z".to_string(),
                reason: RevocationReason::KeyCompromise,
            }],
        };
        let json = serde_json::to_string_pretty(&doc).unwrap();
        let doc2: RevocationDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(doc, doc2);
    }

    #[test]
    fn test_revocation_reason_serde() {
        assert_eq!(
            serde_json::to_string(&RevocationReason::KeyCompromise).unwrap(),
            "\"key_compromise\""
        );
        assert_eq!(
            serde_json::to_string(&RevocationReason::Superseded).unwrap(),
            "\"superseded\""
        );
        assert_eq!(
            serde_json::to_string(&RevocationReason::CessationOfOperation).unwrap(),
            "\"cessation_of_operation\""
        );
        assert_eq!(
            serde_json::to_string(&RevocationReason::PrivilegeWithdrawn).unwrap(),
            "\"privilege_withdrawn\""
        );
    }

    #[test]
    fn test_revocation_document_empty_keys() {
        let json = r#"{
            "schemapin_version": "1.2",
            "domain": "example.com",
            "updated_at": "2026-02-10T00:00:00Z"
        }"#;
        let doc: RevocationDocument = serde_json::from_str(json).unwrap();
        assert!(doc.revoked_keys.is_empty());
    }
}
