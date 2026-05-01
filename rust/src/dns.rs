//! DNS TXT cross-verification (v1.4).
//!
//! A tool provider MAY publish a TXT record at `_schemapin.{domain}` containing
//! the public-key fingerprint advertised in `.well-known/schemapin.json`. When
//! present, clients use it as a *second-channel* verification: the DNS
//! credential chain is independent of the HTTPS hosting credential chain, so
//! compromising one doesn't compromise the other.
//!
//! ## TXT record format
//!
//! ```text
//! _schemapin.example.com. IN TXT "v=schemapin1; kid=acme-2026-01; fp=sha256:a1b2c3..."
//! ```
//!
//! Fields:
//! - `v` — version tag (`schemapin1`); required
//! - `fp` — key fingerprint (`sha256:<hex>`); required, lowercase hex
//! - `kid` — optional key id, used for disambiguating multi-key endpoints
//!
//! ## Verification semantics
//!
//! - **Absent record** → no effect (DNS TXT is optional)
//! - **Present and matching** → confidence boost (recorded in result warnings is *not* used; absence of mismatch is the signal)
//! - **Present and mismatching** → hard failure with [`crate::error::ErrorCode::DomainMismatch`]
//!
//! Use [`parse_txt_record`] to parse a raw TXT string and [`verify_dns_match`]
//! to cross-check it against a discovery document. With the `dns` feature
//! enabled, [`fetch_dns_txt`] performs the actual DNS lookup.

use crate::crypto;
use crate::error::{Error, ErrorCode};
use crate::types::discovery::WellKnownResponse;

/// Parsed `_schemapin.{domain}` TXT record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsTxtRecord {
    pub version: String,
    pub kid: Option<String>,
    /// Lowercase fingerprint string, including the `sha256:` prefix.
    pub fingerprint: String,
}

/// Parse a raw TXT record value (e.g. `"v=schemapin1; kid=acme-2026-01; fp=sha256:..."`).
///
/// Whitespace around `;` and `=` is tolerated. Field order is not significant.
/// Returns an error if the record is missing the required `v` or `fp` fields,
/// or if the version isn't `schemapin1`.
pub fn parse_txt_record(value: &str) -> Result<DnsTxtRecord, Error> {
    let mut version: Option<String> = None;
    let mut kid: Option<String> = None;
    let mut fp: Option<String> = None;

    for raw_part in value.split(';') {
        let part = raw_part.trim();
        if part.is_empty() {
            continue;
        }
        let (k, v) = part.split_once('=').ok_or_else(|| Error::Verification {
            code: ErrorCode::DiscoveryInvalid,
            message: format!("DNS TXT field missing '=': {}", part),
        })?;
        let k = k.trim().to_ascii_lowercase();
        let v = v.trim();
        match k.as_str() {
            "v" => version = Some(v.to_string()),
            "kid" => kid = Some(v.to_string()),
            "fp" => fp = Some(v.to_ascii_lowercase()),
            // Forward-compat: ignore unknown fields rather than reject.
            _ => {}
        }
    }

    let version = version.ok_or_else(|| Error::Verification {
        code: ErrorCode::DiscoveryInvalid,
        message: "DNS TXT record missing required 'v' field".to_string(),
    })?;
    if version != "schemapin1" {
        return Err(Error::Verification {
            code: ErrorCode::DiscoveryInvalid,
            message: format!("DNS TXT unsupported version: {}", version),
        });
    }
    let fingerprint = fp.ok_or_else(|| Error::Verification {
        code: ErrorCode::DiscoveryInvalid,
        message: "DNS TXT record missing required 'fp' field".to_string(),
    })?;
    if !fingerprint.starts_with("sha256:") {
        return Err(Error::Verification {
            code: ErrorCode::DiscoveryInvalid,
            message: format!("DNS TXT 'fp' must be sha256:<hex>: {}", fingerprint),
        });
    }

    Ok(DnsTxtRecord {
        version,
        kid,
        fingerprint,
    })
}

/// Cross-check the DNS TXT record's fingerprint against the discovery document.
///
/// Returns `Ok(())` when the fingerprint matches the SHA-256 fingerprint of
/// the public key in `discovery.public_key_pem`. Returns
/// [`ErrorCode::DomainMismatch`] otherwise.
pub fn verify_dns_match(discovery: &WellKnownResponse, txt: &DnsTxtRecord) -> Result<(), Error> {
    let computed = crypto::calculate_key_id(&discovery.public_key_pem)?.to_ascii_lowercase();
    if computed == txt.fingerprint {
        Ok(())
    } else {
        Err(Error::Verification {
            code: ErrorCode::DomainMismatch,
            message: format!(
                "DNS TXT fingerprint mismatch: discovery={}, dns={}",
                computed, txt.fingerprint
            ),
        })
    }
}

/// Construct the DNS lookup name for a given tool domain.
pub fn txt_record_name(domain: &str) -> String {
    format!("_schemapin.{}", domain.trim_end_matches('.'))
}

/// Fetch and parse the `_schemapin.{domain}` TXT record. Behind the `dns` feature.
///
/// Returns:
/// - `Ok(Some(record))` — record present and parseable
/// - `Ok(None)` — no `_schemapin` TXT record exists for the domain
/// - `Err(_)` — DNS resolution error or the record exists but is malformed
///
/// Multiple matching TXT chunks are joined per RFC 1464 (concatenation in
/// emit order). Multiple separate TXT records at the same name are not
/// supported — the first valid record wins.
#[cfg(feature = "dns")]
pub async fn fetch_dns_txt(domain: &str) -> Result<Option<DnsTxtRecord>, Error> {
    use hickory_resolver::error::ResolveErrorKind;
    use hickory_resolver::TokioAsyncResolver;

    let name = txt_record_name(domain);
    let resolver = TokioAsyncResolver::tokio(Default::default(), Default::default());
    let lookup = match resolver.txt_lookup(&name).await {
        Ok(l) => l,
        Err(e) => {
            if matches!(e.kind(), ResolveErrorKind::NoRecordsFound { .. }) {
                return Ok(None);
            }
            return Err(Error::Verification {
                code: ErrorCode::DiscoveryFetchFailed,
                message: format!("DNS TXT lookup failed for {}: {}", name, e),
            });
        }
    };

    for record in lookup.iter() {
        // hickory yields TxtData as Vec<Box<[u8]>>; concatenate chunks per RFC 1464.
        let joined: String = record
            .iter()
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect::<Vec<_>>()
            .join("");
        if joined.contains("v=schemapin1") {
            return parse_txt_record(&joined).map(Some);
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_key_pair;
    use crate::discovery::build_well_known_response;

    #[test]
    fn test_parse_full_record() {
        let r = parse_txt_record("v=schemapin1; kid=acme-2026-01; fp=sha256:abcd1234").unwrap();
        assert_eq!(r.version, "schemapin1");
        assert_eq!(r.kid.as_deref(), Some("acme-2026-01"));
        assert_eq!(r.fingerprint, "sha256:abcd1234");
    }

    #[test]
    fn test_parse_minimal_record() {
        let r = parse_txt_record("v=schemapin1;fp=sha256:abc").unwrap();
        assert_eq!(r.version, "schemapin1");
        assert_eq!(r.kid, None);
        assert_eq!(r.fingerprint, "sha256:abc");
    }

    #[test]
    fn test_parse_lowercases_fingerprint() {
        let r = parse_txt_record("v=schemapin1; fp=SHA256:ABCDEF").unwrap();
        assert_eq!(r.fingerprint, "sha256:abcdef");
    }

    #[test]
    fn test_parse_tolerates_whitespace_and_order() {
        let r = parse_txt_record("  fp = sha256:beef ;  v = schemapin1  ").unwrap();
        assert_eq!(r.version, "schemapin1");
        assert_eq!(r.fingerprint, "sha256:beef");
    }

    #[test]
    fn test_parse_ignores_unknown_fields() {
        let r = parse_txt_record("v=schemapin1; fp=sha256:abc; future=ignoreme").unwrap();
        assert_eq!(r.fingerprint, "sha256:abc");
    }

    #[test]
    fn test_parse_missing_v_fails() {
        let e = parse_txt_record("fp=sha256:abc").unwrap_err();
        assert!(matches!(
            e,
            Error::Verification {
                code: ErrorCode::DiscoveryInvalid,
                ..
            }
        ));
    }

    #[test]
    fn test_parse_missing_fp_fails() {
        let e = parse_txt_record("v=schemapin1").unwrap_err();
        assert!(matches!(
            e,
            Error::Verification {
                code: ErrorCode::DiscoveryInvalid,
                ..
            }
        ));
    }

    #[test]
    fn test_parse_unsupported_version_fails() {
        assert!(parse_txt_record("v=schemapin99; fp=sha256:abc").is_err());
    }

    #[test]
    fn test_parse_fp_without_sha256_prefix_fails() {
        assert!(parse_txt_record("v=schemapin1; fp=abc").is_err());
    }

    #[test]
    fn test_parse_field_without_equals_fails() {
        assert!(parse_txt_record("v=schemapin1; broken").is_err());
    }

    #[test]
    fn test_verify_match() {
        let kp = generate_key_pair().unwrap();
        let fp = crypto::calculate_key_id(&kp.public_key_pem).unwrap();
        let discovery = build_well_known_response(&kp.public_key_pem, None, vec![], "1.4");
        let txt = DnsTxtRecord {
            version: "schemapin1".to_string(),
            kid: None,
            fingerprint: fp.to_ascii_lowercase(),
        };
        verify_dns_match(&discovery, &txt).unwrap();
    }

    #[test]
    fn test_verify_mismatch_returns_domain_mismatch() {
        let kp = generate_key_pair().unwrap();
        let discovery = build_well_known_response(&kp.public_key_pem, None, vec![], "1.4");
        let txt = DnsTxtRecord {
            version: "schemapin1".to_string(),
            kid: None,
            fingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
        };
        let err = verify_dns_match(&discovery, &txt).unwrap_err();
        match err {
            Error::Verification { code, .. } => assert_eq!(code, ErrorCode::DomainMismatch),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_txt_record_name_strips_trailing_dot() {
        assert_eq!(txt_record_name("example.com"), "_schemapin.example.com");
        assert_eq!(txt_record_name("example.com."), "_schemapin.example.com");
    }
}
