use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonicalize::canonicalize_and_hash;
use crate::crypto;
use crate::discovery::validate_well_known_response;
use crate::error::ErrorCode;
use crate::pinning::{check_pinning, KeyPinStore, PinningResult};
use crate::resolver::SchemaResolver;
use crate::revocation::check_revocation_combined;
use crate::types::discovery::WellKnownResponse;
use crate::types::revocation::RevocationDocument;

/// Structured verification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub developer_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_pinning: Option<KeyPinningStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<ErrorCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPinningStatus {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,
}

impl VerificationResult {
    pub fn success(
        domain: &str,
        developer_name: Option<&str>,
        pin_status: KeyPinningStatus,
    ) -> Self {
        Self {
            valid: true,
            domain: Some(domain.to_string()),
            developer_name: developer_name.map(|s| s.to_string()),
            key_pinning: Some(pin_status),
            error_code: None,
            error_message: None,
            warnings: vec![],
        }
    }

    pub fn failure(code: ErrorCode, message: &str) -> Self {
        Self {
            valid: false,
            domain: None,
            developer_name: None,
            key_pinning: None,
            error_code: Some(code),
            error_message: Some(message.to_string()),
            warnings: vec![],
        }
    }
}

/// Verify a schema offline using caller-provided documents.
///
/// Implements a 7-step verification flow:
/// 1. Validate discovery document
/// 2. Extract public key and compute fingerprint
/// 3. Check revocation (simple list + standalone document)
/// 4. TOFU key pinning
/// 5. Canonicalize schema and compute hash
/// 6. Verify ECDSA signature against hash
/// 7. Return result
pub fn verify_schema_offline(
    schema: &Value,
    signature_b64: &str,
    domain: &str,
    tool_id: &str,
    discovery: &WellKnownResponse,
    revocation: Option<&RevocationDocument>,
    pin_store: &mut KeyPinStore,
) -> VerificationResult {
    // Step 1: Validate discovery document
    if let Err(e) = validate_well_known_response(discovery) {
        return VerificationResult::failure(
            ErrorCode::DiscoveryInvalid,
            &format!("Discovery validation failed: {}", e),
        );
    }

    // Step 2: Extract public key and compute fingerprint
    let fingerprint = match crypto::calculate_key_id(&discovery.public_key_pem) {
        Ok(fp) => fp,
        Err(e) => {
            return VerificationResult::failure(
                ErrorCode::KeyNotFound,
                &format!("Failed to compute key fingerprint: {}", e),
            )
        }
    };

    // Step 3: Check revocation (both simple list and standalone doc)
    if let Err(e) = check_revocation_combined(&discovery.revoked_keys, revocation, &fingerprint) {
        let code = match &e {
            crate::error::Error::Verification { code, .. } => *code,
            _ => ErrorCode::KeyRevoked,
        };
        return VerificationResult::failure(code, &e.to_string());
    }

    // Step 4: TOFU key pinning
    let pin_result = match check_pinning(pin_store, tool_id, domain, &fingerprint) {
        Ok(r) => r,
        Err(e) => {
            return VerificationResult::failure(ErrorCode::KeyPinMismatch, &e.to_string());
        }
    };

    // Step 5: Canonicalize schema and compute hash
    let schema_hash = canonicalize_and_hash(schema);

    // Step 6: Verify ECDSA signature
    let valid =
        match crypto::verify_signature(&discovery.public_key_pem, &schema_hash, signature_b64) {
            Ok(v) => v,
            Err(e) => {
                return VerificationResult::failure(
                    ErrorCode::SignatureInvalid,
                    &format!("Signature verification error: {}", e),
                );
            }
        };

    if !valid {
        return VerificationResult::failure(
            ErrorCode::SignatureInvalid,
            "Schema signature is invalid",
        );
    }

    // Step 7: Build success result
    let pin_status = match pin_result {
        PinningResult::FirstUse => KeyPinningStatus {
            status: "first_use".to_string(),
            first_seen: Some(chrono::Utc::now().to_rfc3339()),
        },
        PinningResult::Matched => {
            let first_seen = pin_store
                .get_tool(tool_id, domain)
                .and_then(|t| t.pinned_keys.first())
                .map(|pk| pk.first_seen.clone());
            KeyPinningStatus {
                status: "pinned".to_string(),
                first_seen,
            }
        }
        PinningResult::Changed => unreachable!("Changed case handled above"),
    };

    VerificationResult::success(domain, discovery.developer_name.as_deref(), pin_status)
}

/// Verify a schema using a sync [`SchemaResolver`].
///
/// Resolves discovery and revocation documents from the resolver, then
/// delegates to [`verify_schema_offline`].
pub fn verify_schema_with_resolver(
    schema: &Value,
    signature_b64: &str,
    domain: &str,
    tool_id: &str,
    resolver: &dyn SchemaResolver,
    pin_store: &mut KeyPinStore,
) -> VerificationResult {
    let discovery = match resolver.resolve_discovery(domain) {
        Ok(doc) => doc,
        Err(e) => {
            return VerificationResult::failure(
                ErrorCode::DiscoveryFetchFailed,
                &format!("Failed to resolve discovery document: {}", e),
            )
        }
    };

    let revocation = match resolver.resolve_revocation(domain, &discovery) {
        Ok(doc) => doc,
        Err(_) => {
            return VerificationResult::failure(
                ErrorCode::DiscoveryFetchFailed,
                "Revocation document unreachable (fail-closed)",
            );
        }
    };

    verify_schema_offline(
        schema,
        signature_b64,
        domain,
        tool_id,
        &discovery,
        revocation.as_ref(),
        pin_store,
    )
}

/// Online verification that fetches discovery/revocation documents.
///
/// Uses [`WellKnownResolver`](crate::resolver::WellKnownResolver) to fetch
/// documents from standard `.well-known` HTTPS endpoints.
#[cfg(feature = "fetch")]
pub async fn verify_schema(
    schema: &Value,
    signature_b64: &str,
    domain: &str,
    tool_id: &str,
    pin_store: &mut KeyPinStore,
) -> VerificationResult {
    // Fetch discovery document
    let discovery = match crate::discovery::fetch_well_known(domain).await {
        Ok(doc) => doc,
        Err(e) => {
            return VerificationResult::failure(
                ErrorCode::DiscoveryFetchFailed,
                &format!("Failed to fetch discovery document: {}", e),
            )
        }
    };

    // Fetch revocation document
    let revocation = if let Some(ref endpoint) = discovery.revocation_endpoint {
        match crate::revocation::fetch_revocation_document(endpoint).await {
            Ok(doc) => Some(doc),
            Err(_) => {
                // Fail closed: if revocation endpoint is unreachable, reject
                return VerificationResult::failure(
                    ErrorCode::DiscoveryFetchFailed,
                    "Revocation endpoint unreachable (fail-closed)",
                );
            }
        }
    } else {
        None
    };

    verify_schema_offline(
        schema,
        signature_b64,
        domain,
        tool_id,
        &discovery,
        revocation.as_ref(),
        pin_store,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonicalize::canonicalize_and_hash;
    use crate::crypto::{generate_key_pair, sign_data};
    use crate::discovery::build_well_known_response;
    use crate::pinning::KeyPinStore;
    use crate::resolver::TrustBundleResolver;
    use crate::revocation::{add_revoked_key, build_revocation_document};
    use crate::types::bundle::{BundledDiscovery, SchemaPinTrustBundle};
    use crate::types::revocation::RevocationReason;
    use serde_json::json;

    struct TestFixture {
        schema: Value,
        signature: String,
        discovery: WellKnownResponse,
        pin_store: KeyPinStore,
    }

    fn setup() -> TestFixture {
        let kp = generate_key_pair().unwrap();
        let schema = json!({
            "name": "calculate_sum",
            "description": "Calculates the sum of two numbers",
            "parameters": { "a": "integer", "b": "integer" }
        });
        let hash = canonicalize_and_hash(&schema);
        let signature = sign_data(&kp.private_key_pem, &hash).unwrap();
        let discovery =
            build_well_known_response(&kp.public_key_pem, Some("Test Developer"), vec![], "1.2");

        TestFixture {
            schema,
            signature,
            discovery,
            pin_store: KeyPinStore::new(),
        }
    }

    #[test]
    fn test_happy_path_verification() {
        let mut f = setup();
        let result = verify_schema_offline(
            &f.schema,
            &f.signature,
            "example.com",
            "calculate_sum",
            &f.discovery,
            None,
            &mut f.pin_store,
        );
        assert!(result.valid, "Expected valid, got: {:?}", result);
        assert_eq!(result.domain, Some("example.com".to_string()));
        assert_eq!(result.developer_name, Some("Test Developer".to_string()));
    }

    #[test]
    fn test_invalid_signature() {
        let mut f = setup();
        let result = verify_schema_offline(
            &f.schema,
            "bm90LWEtdmFsaWQtc2lnbmF0dXJl",
            "example.com",
            "calculate_sum",
            &f.discovery,
            None,
            &mut f.pin_store,
        );
        assert!(!result.valid);
        assert_eq!(result.error_code, Some(ErrorCode::SignatureInvalid));
    }

    #[test]
    fn test_tampered_schema() {
        let mut f = setup();
        let tampered = json!({
            "name": "calculate_sum",
            "description": "TAMPERED description",
            "parameters": { "a": "integer", "b": "integer" }
        });
        let result = verify_schema_offline(
            &tampered,
            &f.signature,
            "example.com",
            "calculate_sum",
            &f.discovery,
            None,
            &mut f.pin_store,
        );
        assert!(!result.valid);
        assert_eq!(result.error_code, Some(ErrorCode::SignatureInvalid));
    }

    #[test]
    fn test_revoked_key() {
        let mut f = setup();
        let fingerprint = crypto::calculate_key_id(&f.discovery.public_key_pem).unwrap();
        f.discovery.revoked_keys = vec![fingerprint];

        let result = verify_schema_offline(
            &f.schema,
            &f.signature,
            "example.com",
            "calculate_sum",
            &f.discovery,
            None,
            &mut f.pin_store,
        );
        assert!(!result.valid);
        assert_eq!(result.error_code, Some(ErrorCode::KeyRevoked));
    }

    #[test]
    fn test_revoked_key_in_doc() {
        let mut f = setup();
        let fingerprint = crypto::calculate_key_id(&f.discovery.public_key_pem).unwrap();
        let mut rev_doc = build_revocation_document("example.com");
        add_revoked_key(&mut rev_doc, &fingerprint, RevocationReason::KeyCompromise);

        let result = verify_schema_offline(
            &f.schema,
            &f.signature,
            "example.com",
            "calculate_sum",
            &f.discovery,
            Some(&rev_doc),
            &mut f.pin_store,
        );
        assert!(!result.valid);
        assert_eq!(result.error_code, Some(ErrorCode::KeyRevoked));
    }

    #[test]
    fn test_key_pin_change_rejected() {
        let mut f = setup();
        // First verification pins the key
        let result1 = verify_schema_offline(
            &f.schema,
            &f.signature,
            "example.com",
            "calculate_sum",
            &f.discovery,
            None,
            &mut f.pin_store,
        );
        assert!(result1.valid);

        // Now change the key
        let kp2 = generate_key_pair().unwrap();
        let hash = canonicalize_and_hash(&f.schema);
        let sig2 = sign_data(&kp2.private_key_pem, &hash).unwrap();
        let disc2 = build_well_known_response(
            &kp2.public_key_pem,
            Some("Different Developer"),
            vec![],
            "1.2",
        );

        let result2 = verify_schema_offline(
            &f.schema,
            &sig2,
            "example.com",
            "calculate_sum",
            &disc2,
            None,
            &mut f.pin_store,
        );
        assert!(!result2.valid);
        assert_eq!(result2.error_code, Some(ErrorCode::KeyPinMismatch));
    }

    #[test]
    fn test_first_use_pinning_status() {
        let mut f = setup();
        let result = verify_schema_offline(
            &f.schema,
            &f.signature,
            "example.com",
            "calculate_sum",
            &f.discovery,
            None,
            &mut f.pin_store,
        );
        assert!(result.valid);
        let pin = result.key_pinning.unwrap();
        assert_eq!(pin.status, "first_use");
        assert!(pin.first_seen.is_some());
    }

    #[test]
    fn test_matched_pinning_status() {
        let mut f = setup();
        // First verification
        verify_schema_offline(
            &f.schema,
            &f.signature,
            "example.com",
            "calculate_sum",
            &f.discovery,
            None,
            &mut f.pin_store,
        );
        // Second verification
        let result = verify_schema_offline(
            &f.schema,
            &f.signature,
            "example.com",
            "calculate_sum",
            &f.discovery,
            None,
            &mut f.pin_store,
        );
        assert!(result.valid);
        let pin = result.key_pinning.unwrap();
        assert_eq!(pin.status, "pinned");
    }

    #[test]
    fn test_verify_with_trust_bundle_resolver() {
        let f = setup();
        let bundle = SchemaPinTrustBundle {
            schemapin_bundle_version: "1.2".to_string(),
            created_at: "2026-02-10T00:00:00Z".to_string(),
            documents: vec![BundledDiscovery {
                domain: "example.com".to_string(),
                well_known: f.discovery.clone(),
            }],
            revocations: vec![],
        };
        let resolver = TrustBundleResolver::new(&bundle);
        let mut pin_store = KeyPinStore::new();

        let result = verify_schema_with_resolver(
            &f.schema,
            &f.signature,
            "example.com",
            "calculate_sum",
            &resolver,
            &mut pin_store,
        );
        assert!(result.valid, "Expected valid, got: {:?}", result);
        assert_eq!(result.domain, Some("example.com".to_string()));
    }

    #[test]
    fn test_verify_with_resolver_missing_domain() {
        let f = setup();
        let bundle = SchemaPinTrustBundle::new("2026-02-10T00:00:00Z");
        let resolver = TrustBundleResolver::new(&bundle);
        let mut pin_store = KeyPinStore::new();

        let result = verify_schema_with_resolver(
            &f.schema,
            &f.signature,
            "example.com",
            "calculate_sum",
            &resolver,
            &mut pin_store,
        );
        assert!(!result.valid);
        assert_eq!(result.error_code, Some(ErrorCode::DiscoveryFetchFailed));
    }

    #[test]
    fn test_invalid_discovery_document() {
        let mut f = setup();
        f.discovery.public_key_pem = "".to_string();

        let result = verify_schema_offline(
            &f.schema,
            &f.signature,
            "example.com",
            "calculate_sum",
            &f.discovery,
            None,
            &mut f.pin_store,
        );
        assert!(!result.valid);
        assert_eq!(result.error_code, Some(ErrorCode::DiscoveryInvalid));
    }
}
