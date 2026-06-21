use serde::{Deserialize, Serialize};

use super::discovery::WellKnownResponse;
use super::revocation::RevocationDocument;

/// A pre-shared collection of discovery and revocation documents for offline verification.
///
/// v1.4 adds optional distribution fields (`bundle_authority`, `signed_at`,
/// `expires_at`, `signature`) so bundles can be signed by a bundle authority and
/// safely exchanged between agents over A2A. See [`crate::bundle`] for the
/// sign / verify / merge operations.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaPinTrustBundle {
    pub schemapin_bundle_version: String,
    pub created_at: String,
    pub documents: Vec<BundledDiscovery>,
    #[serde(default)]
    pub revocations: Vec<RevocationDocument>,
    /// (v1.4) The authority that signed this bundle. Present on signed bundles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_authority: Option<BundleAuthority>,
    /// (v1.4) RFC 3339 timestamp the bundle was signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<String>,
    /// (v1.4) Optional RFC 3339 expiry; verifiers reject the bundle past this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// (v1.4) Base64 DER ECDSA P-256 signature over the canonical bundle bytes
    /// (`schemapin-v1` canonicalization with this field set to `""`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// (v1.4) Identifies and carries the public key of the authority that signed a
/// trust bundle. TOFU-pinned by `kid` on first use (see
/// [`crate::bundle::verify_trust_bundle`]).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleAuthority {
    pub kid: String,
    pub public_key_pem: String,
}

/// A discovery document bundled with its domain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundledDiscovery {
    pub domain: String,
    #[serde(flatten)]
    pub well_known: WellKnownResponse,
}

impl SchemaPinTrustBundle {
    /// Create a new empty trust bundle.
    pub fn new(created_at: &str) -> Self {
        Self {
            schemapin_bundle_version: "1.2".to_string(),
            created_at: created_at.to_string(),
            documents: vec![],
            revocations: vec![],
            bundle_authority: None,
            signed_at: None,
            expires_at: None,
            signature: None,
        }
    }

    /// Find a discovery document by domain.
    pub fn find_discovery(&self, domain: &str) -> Option<&BundledDiscovery> {
        self.documents.iter().find(|d| d.domain == domain)
    }

    /// Find a revocation document by domain.
    pub fn find_revocation(&self, domain: &str) -> Option<&RevocationDocument> {
        self.revocations.iter().find(|r| r.domain == domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_bundle() -> SchemaPinTrustBundle {
        SchemaPinTrustBundle {
            schemapin_bundle_version: "1.2".to_string(),
            created_at: "2026-02-10T00:00:00Z".to_string(),
            documents: vec![BundledDiscovery {
                domain: "example.com".to_string(),
                well_known: WellKnownResponse {
                    schema_version: "1.2".to_string(),
                    developer_name: Some("Example Corp".to_string()),
                    public_key_pem: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
                        .to_string(),
                    revoked_keys: vec![],
                    contact: None,
                    revocation_endpoint: None,
                },
            }],
            revocations: vec![],
            ..Default::default()
        }
    }

    #[test]
    fn test_trust_bundle_serde_roundtrip() {
        let bundle = make_test_bundle();
        let json = serde_json::to_string_pretty(&bundle).unwrap();
        let bundle2: SchemaPinTrustBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle, bundle2);
    }

    #[test]
    fn test_find_discovery() {
        let bundle = make_test_bundle();
        assert!(bundle.find_discovery("example.com").is_some());
        assert!(bundle.find_discovery("other.com").is_none());
    }

    #[test]
    fn test_find_revocation() {
        let bundle = make_test_bundle();
        assert!(bundle.find_revocation("example.com").is_none());
    }

    #[test]
    fn test_new_bundle() {
        let bundle = SchemaPinTrustBundle::new("2026-02-10T00:00:00Z");
        assert_eq!(bundle.schemapin_bundle_version, "1.2");
        assert!(bundle.documents.is_empty());
        assert!(bundle.revocations.is_empty());
    }

    #[test]
    fn test_bundled_discovery_flattening() {
        let bd = BundledDiscovery {
            domain: "example.com".to_string(),
            well_known: WellKnownResponse {
                schema_version: "1.2".to_string(),
                developer_name: Some("Test".to_string()),
                public_key_pem: "key".to_string(),
                revoked_keys: vec![],
                contact: None,
                revocation_endpoint: None,
            },
        };
        let json = serde_json::to_string(&bd).unwrap();
        // Flattened fields should appear at the top level
        assert!(json.contains("\"domain\""));
        assert!(json.contains("\"schema_version\""));
        assert!(json.contains("\"public_key_pem\""));
    }
}
