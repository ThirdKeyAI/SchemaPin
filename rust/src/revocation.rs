use chrono::Utc;

use crate::error::{Error, ErrorCode};
use crate::types::revocation::{RevocationDocument, RevocationReason, RevokedKey};

/// Build an empty revocation document for a domain.
pub fn build_revocation_document(domain: &str) -> RevocationDocument {
    RevocationDocument {
        schemapin_version: "1.2".to_string(),
        domain: domain.to_string(),
        updated_at: Utc::now().to_rfc3339(),
        revoked_keys: vec![],
    }
}

/// Add a revoked key to the document.
pub fn add_revoked_key(doc: &mut RevocationDocument, fingerprint: &str, reason: RevocationReason) {
    doc.revoked_keys.push(RevokedKey {
        fingerprint: fingerprint.to_string(),
        revoked_at: Utc::now().to_rfc3339(),
        reason,
    });
    doc.updated_at = Utc::now().to_rfc3339();
}

/// Check if a key fingerprint is revoked in a standalone revocation document.
/// Returns `Ok(())` if the key is not revoked, or `Err` if it is.
pub fn check_revocation(doc: &RevocationDocument, fingerprint: &str) -> Result<(), Error> {
    if let Some(rk) = doc
        .revoked_keys
        .iter()
        .find(|rk| rk.fingerprint == fingerprint)
    {
        return Err(Error::Verification {
            code: ErrorCode::KeyRevoked,
            message: format!("Key {} revoked: {:?}", fingerprint, rk.reason),
        });
    }
    Ok(())
}

/// Combined revocation check: checks both the simple revoked_keys list (from
/// the well-known response) and a standalone revocation document.
pub fn check_revocation_combined(
    simple_revoked: &[String],
    revocation_doc: Option<&RevocationDocument>,
    fingerprint: &str,
) -> Result<(), Error> {
    // Check simple list first
    if simple_revoked.iter().any(|k| k == fingerprint) {
        return Err(Error::Verification {
            code: ErrorCode::KeyRevoked,
            message: format!("Key {} found in revoked_keys list", fingerprint),
        });
    }
    // Check standalone doc
    if let Some(doc) = revocation_doc {
        check_revocation(doc, fingerprint)?;
    }
    Ok(())
}

/// Fetch a revocation document from a URL.
#[cfg(feature = "fetch")]
pub async fn fetch_revocation_document(url: &str) -> Result<RevocationDocument, Error> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| Error::Revocation(e.to_string()))?;

    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| Error::Revocation(format!("Failed to fetch {}: {}", url, e)))?;

    if !resp.status().is_success() {
        return Err(Error::Revocation(format!(
            "HTTP {} fetching {}",
            resp.status(),
            url
        )));
    }

    let doc: RevocationDocument = resp
        .json()
        .await
        .map_err(|e| Error::Revocation(format!("Invalid JSON from {}: {}", url, e)))?;

    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_revocation_document() {
        let doc = build_revocation_document("example.com");
        assert_eq!(doc.domain, "example.com");
        assert_eq!(doc.schemapin_version, "1.2");
        assert!(doc.revoked_keys.is_empty());
    }

    #[test]
    fn test_add_revoked_key() {
        let mut doc = build_revocation_document("example.com");
        add_revoked_key(&mut doc, "sha256:abc123", RevocationReason::KeyCompromise);
        assert_eq!(doc.revoked_keys.len(), 1);
        assert_eq!(doc.revoked_keys[0].fingerprint, "sha256:abc123");
        assert_eq!(doc.revoked_keys[0].reason, RevocationReason::KeyCompromise);
    }

    #[test]
    fn test_check_revocation_clean() {
        let doc = build_revocation_document("example.com");
        assert!(check_revocation(&doc, "sha256:abc123").is_ok());
    }

    #[test]
    fn test_check_revocation_revoked() {
        let mut doc = build_revocation_document("example.com");
        add_revoked_key(&mut doc, "sha256:abc123", RevocationReason::Superseded);
        assert!(check_revocation(&doc, "sha256:abc123").is_err());
        assert!(check_revocation(&doc, "sha256:other").is_ok());
    }

    #[test]
    fn test_check_revocation_combined_simple_list() {
        let simple = vec!["sha256:revoked1".to_string()];
        assert!(check_revocation_combined(&simple, None, "sha256:revoked1").is_err());
        assert!(check_revocation_combined(&simple, None, "sha256:clean").is_ok());
    }

    #[test]
    fn test_check_revocation_combined_doc() {
        let mut doc = build_revocation_document("example.com");
        add_revoked_key(&mut doc, "sha256:revoked2", RevocationReason::KeyCompromise);

        assert!(check_revocation_combined(&[], Some(&doc), "sha256:revoked2").is_err());
        assert!(check_revocation_combined(&[], Some(&doc), "sha256:clean").is_ok());
    }

    #[test]
    fn test_check_revocation_combined_both() {
        let simple = vec!["sha256:simple_revoked".to_string()];
        let mut doc = build_revocation_document("example.com");
        add_revoked_key(&mut doc, "sha256:doc_revoked", RevocationReason::Superseded);

        assert!(check_revocation_combined(&simple, Some(&doc), "sha256:simple_revoked").is_err());
        assert!(check_revocation_combined(&simple, Some(&doc), "sha256:doc_revoked").is_err());
        assert!(check_revocation_combined(&simple, Some(&doc), "sha256:clean").is_ok());
    }
}
