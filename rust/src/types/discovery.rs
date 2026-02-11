use serde::{Deserialize, Serialize};

/// Response from the `.well-known/schemapin.json` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WellKnownResponse {
    pub schema_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub developer_name: Option<String>,
    pub public_key_pem: String,
    #[serde(default)]
    pub revoked_keys: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_well_known_response_serde_roundtrip() {
        let resp = WellKnownResponse {
            schema_version: "1.2".to_string(),
            developer_name: Some("Example Corp".to_string()),
            public_key_pem: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
                .to_string(),
            revoked_keys: vec![
                "sha256:abc123def456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                    .to_string(),
            ],
            contact: Some("security@example.com".to_string()),
            revocation_endpoint: Some(
                "https://example.com/.well-known/schemapin-revocations.json".to_string(),
            ),
        };
        let json = serde_json::to_string_pretty(&resp).unwrap();
        let resp2: WellKnownResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, resp2);
    }

    #[test]
    fn test_well_known_response_minimal() {
        let json = r#"{
            "schema_version": "1.0",
            "public_key_pem": "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
        }"#;
        let resp: WellKnownResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.schema_version, "1.0");
        assert!(resp.developer_name.is_none());
        assert!(resp.revoked_keys.is_empty());
        assert!(resp.contact.is_none());
        assert!(resp.revocation_endpoint.is_none());
    }

    #[test]
    fn test_well_known_response_optional_fields_skip() {
        let resp = WellKnownResponse {
            schema_version: "1.2".to_string(),
            developer_name: None,
            public_key_pem: "key".to_string(),
            revoked_keys: vec![],
            contact: None,
            revocation_endpoint: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("developer_name"));
        assert!(!json.contains("contact"));
        assert!(!json.contains("revocation_endpoint"));
    }
}
