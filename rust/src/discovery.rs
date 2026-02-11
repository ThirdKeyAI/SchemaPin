use crate::error::Error;
use crate::types::discovery::WellKnownResponse;

/// Construct the `.well-known` URL for a domain.
pub fn construct_well_known_url(domain: &str) -> String {
    format!("https://{}/.well-known/schemapin.json", domain)
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
#[cfg(feature = "fetch")]
pub async fn fetch_well_known(domain: &str) -> Result<WellKnownResponse, Error> {
    let url = construct_well_known_url(domain);
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| Error::Discovery(e.to_string()))?;

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| Error::Discovery(format!("Failed to fetch {}: {}", url, e)))?;

    if resp.status().is_redirection() {
        return Err(Error::Discovery(format!(
            "Redirect detected fetching {} (status {}). Redirects are not allowed.",
            url,
            resp.status()
        )));
    }

    if !resp.status().is_success() {
        return Err(Error::Discovery(format!(
            "HTTP {} fetching {}",
            resp.status(),
            url
        )));
    }

    let well_known: WellKnownResponse = resp
        .json()
        .await
        .map_err(|e| Error::Discovery(format!("Invalid JSON from {}: {}", url, e)))?;

    validate_well_known_response(&well_known)?;
    Ok(well_known)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_construct_well_known_url() {
        assert_eq!(
            construct_well_known_url("example.com"),
            "https://example.com/.well-known/schemapin.json"
        );
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
