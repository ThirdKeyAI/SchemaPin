use crate::domain::validate_domain;
use crate::error::Error;
use crate::types::discovery::WellKnownResponse;

/// Construct the `.well-known` URL for a domain.
///
/// `domain` must be a bare hostname (an `https://` prefix is tolerated and
/// stripped); `http://` is refused because the spec requires HTTPS and a
/// plaintext first fetch would let a network attacker pin their own key.
pub fn construct_well_known_url(domain: &str) -> Result<String, Error> {
    if domain.starts_with("http://") {
        return Err(Error::InvalidDomain(
            "SchemaPin discovery requires https; http:// is not permitted".to_string(),
        ));
    }
    let bare = domain
        .strip_prefix("https://")
        .unwrap_or(domain)
        .trim_end_matches('/');
    let normalized = validate_domain(bare)?;
    Ok(format!("https://{}/.well-known/schemapin.json", normalized))
}

/// Validate a well-known response for basic structural requirements.
pub fn validate_well_known_response(response: &WellKnownResponse) -> Result<(), Error> {
    if response.public_key_pem.is_empty() {
        return Err(Error::Discovery(
            "public_key_pem must not be empty".to_string(),
        ));
    }
    if !response
        .public_key_pem
        .contains("-----BEGIN PUBLIC KEY-----")
    {
        return Err(Error::Discovery(
            "public_key_pem must be a valid PEM public key".to_string(),
        ));
    }
    if response.schema_version.is_empty() {
        return Err(Error::Discovery(
            "schema_version must not be empty".to_string(),
        ));
    }
    Ok(())
}

/// Build a well-known response with the given fields.
pub fn build_well_known_response(
    public_key_pem: &str,
    developer_name: Option<&str>,
    revoked_keys: Vec<String>,
    schema_version: &str,
) -> WellKnownResponse {
    WellKnownResponse {
        schema_version: schema_version.to_string(),
        developer_name: developer_name.map(|s| s.to_string()),
        public_key_pem: public_key_pem.to_string(),
        revoked_keys,
        contact: None,
        revocation_endpoint: None,
    }
}

/// Check if a key fingerprint appears in the revoked keys list.
pub fn check_key_revocation(fingerprint: &str, revoked_keys: &[String]) -> bool {
    revoked_keys.iter().any(|k| k == fingerprint)
}

/// Fetch a well-known response from a domain over HTTPS.
///
/// Uses the hardened transport: https only, no redirects, capped body,
/// timeouts.
#[cfg(feature = "fetch")]
pub async fn fetch_well_known(domain: &str) -> Result<WellKnownResponse, Error> {
    let url = construct_well_known_url(domain)?;
    let well_known: WellKnownResponse = crate::transport::fetch_json(&url)
        .await
        .map_err(|e| Error::Discovery(e.to_string()))?;
    validate_well_known_response(&well_known)?;
    Ok(well_known)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_construct_well_known_url() {
        assert_eq!(
            construct_well_known_url("example.com").unwrap(),
            "https://example.com/.well-known/schemapin.json"
        );
        assert_eq!(
            construct_well_known_url("https://Example.COM/").unwrap(),
            "https://example.com/.well-known/schemapin.json"
        );
        for bad in [
            "http://example.com",
            "example.com:8080",
            "example.com/x",
            "10.0.0.1",
            "localhost",
            "../evil",
            "good.com@evil.com",
        ] {
            assert!(
                construct_well_known_url(bad).is_err(),
                "{:?} must fail",
                bad
            );
        }
    }

    #[test]
    fn test_validate_well_known_response_valid() {
        let resp = build_well_known_response(
            "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
            Some("Test"),
            vec![],
            "1.2",
        );
        assert!(validate_well_known_response(&resp).is_ok());
    }

    #[test]
    fn test_validate_well_known_response_empty_key() {
        let resp = WellKnownResponse {
            schema_version: "1.2".to_string(),
            developer_name: None,
            public_key_pem: "".to_string(),
            revoked_keys: vec![],
            contact: None,
            revocation_endpoint: None,
        };
        assert!(validate_well_known_response(&resp).is_err());
    }

    #[test]
    fn test_validate_well_known_response_bad_pem() {
        let resp = WellKnownResponse {
            schema_version: "1.2".to_string(),
            developer_name: None,
            public_key_pem: "not-a-pem-key".to_string(),
            revoked_keys: vec![],
            contact: None,
            revocation_endpoint: None,
        };
        assert!(validate_well_known_response(&resp).is_err());
    }

    #[test]
    fn test_check_key_revocation() {
        let revoked = vec!["sha256:abc123".to_string(), "sha256:def456".to_string()];
        assert!(check_key_revocation("sha256:abc123", &revoked));
        assert!(check_key_revocation("sha256:def456", &revoked));
        assert!(!check_key_revocation("sha256:xyz789", &revoked));
    }

    #[test]
    fn test_check_key_revocation_empty() {
        assert!(!check_key_revocation("sha256:abc123", &[]));
    }

    #[test]
    fn test_build_well_known_response() {
        let resp = build_well_known_response(
            "-----BEGIN PUBLIC KEY-----\nkey\n-----END PUBLIC KEY-----",
            Some("Developer"),
            vec!["sha256:old".to_string()],
            "1.2",
        );
        assert_eq!(resp.schema_version, "1.2");
        assert_eq!(resp.developer_name, Some("Developer".to_string()));
        assert_eq!(resp.revoked_keys.len(), 1);
    }
}
