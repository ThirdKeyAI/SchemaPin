//! (v1.4) Trust-bundle distribution for A2A networks.
//!
//! Lets a *bundle authority* sign a [`SchemaPinTrustBundle`] so it can be
//! exchanged between agents over A2A without per-bundle out-of-band trust
//! establishment. Provides:
//!
//! - [`sign_trust_bundle`] / [`verify_trust_bundle`] — ECDSA P-256 over the
//!   canonical bundle bytes, with TOFU pinning of the authority key by `kid`.
//! - [`merge_trust_bundles`] — combine bundles from multiple sources, newest
//!   entry wins per domain.
//! - [`build_trust_bundle_request`] / [`build_trust_bundle_response`] /
//!   [`parse_trust_bundle_response`] — the `schemapin/trustBundle` JSON-RPC
//!   envelope for A2A bundle exchange.
//!
//! ## Signing input
//!
//! The signature covers the `schemapin-v1` canonicalization (recursive sorted
//! keys, compact, UTF-8) of the entire bundle object with the `signature` field
//! set to the empty string `""`. All four SDKs build the identical byte string,
//! so a bundle signed by any SDK verifies in every other.

use serde_json::{json, Value};

use crate::canonicalize::canonicalize_schema;
use crate::crypto::{calculate_key_id, sign_data, verify_signature, KeyManager};
use crate::error::{Error, ErrorCode};
use crate::pinning::{check_pinning, KeyPinStore};
use crate::types::bundle::{BundleAuthority, SchemaPinTrustBundle};

/// Bundle-distribution wire format version stamped on signed bundles.
pub const BUNDLE_VERSION_SIGNED: &str = "1.4";

/// Sentinel "domain" used to key bundle-authority pins in a [`KeyPinStore`].
/// Authorities are pinned by `kid`, independent of any tool domain.
pub const BUNDLE_AUTHORITY_PIN_DOMAIN: &str = "_bundle_authority";

/// Build the canonical bytes that a bundle's signature covers: the bundle with
/// its `signature` field forced to `""`, `schemapin-v1`-canonicalized.
fn signing_bytes(bundle: &SchemaPinTrustBundle) -> Result<String, Error> {
    let mut value = serde_json::to_value(bundle)?;
    if let Value::Object(map) = &mut value {
        map.insert("signature".to_string(), Value::String(String::new()));
    }
    Ok(canonicalize_schema(&value))
}

/// Sign a trust bundle with a bundle-authority key.
///
/// Stamps `bundle_authority` (derived public key + `kid`),
/// `schemapin_bundle_version = "1.4"`, `signed_at`, and optional `expires_at`,
/// then writes the base64 DER ECDSA P-256 `signature`. `signed_at` /
/// `expires_at` are caller-supplied RFC 3339 strings (kept out of the core so
/// signing is deterministic and cross-language testable).
pub fn sign_trust_bundle(
    bundle: &SchemaPinTrustBundle,
    private_key_pem: &str,
    kid: &str,
    signed_at: &str,
    expires_at: Option<&str>,
) -> Result<SchemaPinTrustBundle, Error> {
    let secret = KeyManager::load_private_key_pem(private_key_pem)?;
    let public_key_pem = KeyManager::export_public_key_pem(&secret.public_key())?;

    let mut signed = bundle.clone();
    signed.schemapin_bundle_version = BUNDLE_VERSION_SIGNED.to_string();
    signed.bundle_authority = Some(BundleAuthority {
        kid: kid.to_string(),
        public_key_pem,
    });
    signed.signed_at = Some(signed_at.to_string());
    signed.expires_at = expires_at.map(|s| s.to_string());
    signed.signature = None;

    let canonical = signing_bytes(&signed)?;
    signed.signature = Some(sign_data(private_key_pem, canonical.as_bytes())?);
    Ok(signed)
}

/// Verify a signed trust bundle and TOFU-pin its authority key by `kid`.
///
/// Steps: require `bundle_authority` + `signature`; reject when `expires_at`
/// is in the past; TOFU-pin the authority's key fingerprint by `kid` (mismatch
/// → `KEY_PIN_MISMATCH`); verify the signature over the canonical bytes
/// (failure → `SIGNATURE_INVALID`).
pub fn verify_trust_bundle(
    bundle: &SchemaPinTrustBundle,
    authority_pin_store: &mut KeyPinStore,
) -> Result<(), Error> {
    let authority = bundle.bundle_authority.as_ref().ok_or(Error::Verification {
        code: ErrorCode::BundleUnsigned,
        message: "trust bundle has no bundle_authority".to_string(),
    })?;
    let signature = bundle.signature.as_ref().ok_or(Error::Verification {
        code: ErrorCode::BundleUnsigned,
        message: "trust bundle has no signature".to_string(),
    })?;

    if let Some(expires_at) = &bundle.expires_at {
        let exp = chrono::DateTime::parse_from_rfc3339(expires_at).map_err(|e| {
            Error::Verification {
                code: ErrorCode::BundleExpired,
                message: format!("unparseable expires_at '{}': {}", expires_at, e),
            }
        })?;
        if chrono::Utc::now() > exp {
            return Err(Error::Verification {
                code: ErrorCode::BundleExpired,
                message: format!("trust bundle expired at {}", expires_at),
            });
        }
    }

    let fingerprint = calculate_key_id(&authority.public_key_pem)?;
    check_pinning(
        authority_pin_store,
        &authority.kid,
        BUNDLE_AUTHORITY_PIN_DOMAIN,
        &fingerprint,
    )?;

    let canonical = signing_bytes(bundle)?;
    if verify_signature(&authority.public_key_pem, canonical.as_bytes(), signature)? {
        Ok(())
    } else {
        Err(Error::Verification {
            code: ErrorCode::SignatureInvalid,
            message: "trust bundle signature does not verify".to_string(),
        })
    }
}

/// Merge trust bundles, deduplicating discovery + revocation documents by
/// domain. When two bundles carry the same domain, the entry from the bundle
/// with the newer timestamp (`signed_at`, else `created_at`) wins.
///
/// The result is an *unsigned* bundle (a merge cannot carry a single
/// authority's signature) stamped `schemapin_bundle_version = "1.4"` with
/// `created_at` set to the newest source timestamp. Re-sign it with
/// [`sign_trust_bundle`] before redistribution.
pub fn merge_trust_bundles(bundles: &[SchemaPinTrustBundle]) -> SchemaPinTrustBundle {
    use std::collections::HashMap;

    // domain -> (timestamp, document)
    let mut docs: HashMap<String, (String, _)> = HashMap::new();
    let mut revs: HashMap<String, (String, _)> = HashMap::new();
    let mut newest_ts = String::new();

    for b in bundles {
        let ts = b
            .signed_at
            .clone()
            .unwrap_or_else(|| b.created_at.clone());
        if ts > newest_ts {
            newest_ts = ts.clone();
        }
        for d in &b.documents {
            match docs.get(&d.domain) {
                Some((existing_ts, _)) if *existing_ts >= ts => {}
                _ => {
                    docs.insert(d.domain.clone(), (ts.clone(), d.clone()));
                }
            }
        }
        for r in &b.revocations {
            match revs.get(&r.domain) {
                Some((existing_ts, _)) if *existing_ts >= ts => {}
                _ => {
                    revs.insert(r.domain.clone(), (ts.clone(), r.clone()));
                }
            }
        }
    }

    let mut documents: Vec<_> = docs.into_values().map(|(_, d)| d).collect();
    documents.sort_by(|a, b| a.domain.cmp(&b.domain));
    let mut revocations: Vec<_> = revs.into_values().map(|(_, r)| r).collect();
    revocations.sort_by(|a, b| a.domain.cmp(&b.domain));

    SchemaPinTrustBundle {
        schemapin_bundle_version: BUNDLE_VERSION_SIGNED.to_string(),
        created_at: newest_ts,
        documents,
        revocations,
        ..Default::default()
    }
}

/// Build a `schemapin/trustBundle` JSON-RPC request. `domain` optionally scopes
/// the request to a single provider; omit for "send your whole bundle".
pub fn build_trust_bundle_request(domain: Option<&str>, id: Value) -> Value {
    let params = match domain {
        Some(d) => json!({ "domain": d }),
        None => json!({}),
    };
    json!({
        "jsonrpc": "2.0",
        "method": "schemapin/trustBundle",
        "params": params,
        "id": id,
    })
}

/// Build a `schemapin/trustBundle` JSON-RPC response carrying a signed bundle.
pub fn build_trust_bundle_response(
    bundle: &SchemaPinTrustBundle,
    id: Value,
) -> Result<Value, Error> {
    Ok(json!({
        "jsonrpc": "2.0",
        "result": { "bundle": serde_json::to_value(bundle)? },
        "id": id,
    }))
}

/// Extract the bundle from a `schemapin/trustBundle` JSON-RPC response.
pub fn parse_trust_bundle_response(response: &Value) -> Result<SchemaPinTrustBundle, Error> {
    let bundle = response
        .get("result")
        .and_then(|r| r.get("bundle"))
        .ok_or(Error::Verification {
            code: ErrorCode::DiscoveryInvalid,
            message: "JSON-RPC response missing result.bundle".to_string(),
        })?;
    Ok(serde_json::from_value(bundle.clone())?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_key_pair;
    use crate::types::bundle::BundledDiscovery;
    use crate::types::discovery::WellKnownResponse;

    fn make_bundle(domain: &str, created_at: &str) -> SchemaPinTrustBundle {
        SchemaPinTrustBundle {
            schemapin_bundle_version: "1.2".to_string(),
            created_at: created_at.to_string(),
            documents: vec![BundledDiscovery {
                domain: domain.to_string(),
                well_known: WellKnownResponse {
                    schema_version: "1.2".to_string(),
                    developer_name: Some("Example".to_string()),
                    public_key_pem: "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----"
                        .to_string(),
                    revoked_keys: vec![],
                    contact: None,
                    revocation_endpoint: None,
                },
            }],
            ..Default::default()
        }
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let kp = generate_key_pair().unwrap();
        let bundle = make_bundle("example.com", "2026-05-15T00:00:00Z");
        let signed = sign_trust_bundle(
            &bundle,
            &kp.private_key_pem,
            "auth-2026-05",
            "2026-05-15T00:00:00Z",
            None,
        )
        .unwrap();

        assert_eq!(signed.schemapin_bundle_version, "1.4");
        assert!(signed.signature.is_some());
        assert_eq!(signed.bundle_authority.as_ref().unwrap().kid, "auth-2026-05");

        let mut store = KeyPinStore::new();
        verify_trust_bundle(&signed, &mut store).unwrap();
    }

    #[test]
    fn test_tampered_bundle_fails() {
        let kp = generate_key_pair().unwrap();
        let bundle = make_bundle("example.com", "2026-05-15T00:00:00Z");
        let mut signed = sign_trust_bundle(
            &bundle,
            &kp.private_key_pem,
            "auth",
            "2026-05-15T00:00:00Z",
            None,
        )
        .unwrap();
        // Mutate a signed field.
        signed.documents[0].domain = "evil.com".to_string();

        let mut store = KeyPinStore::new();
        let err = verify_trust_bundle(&signed, &mut store).unwrap_err();
        assert!(matches!(
            err,
            Error::Verification {
                code: ErrorCode::SignatureInvalid,
                ..
            }
        ));
    }

    #[test]
    fn test_unsigned_bundle_rejected() {
        let bundle = make_bundle("example.com", "2026-05-15T00:00:00Z");
        let mut store = KeyPinStore::new();
        let err = verify_trust_bundle(&bundle, &mut store).unwrap_err();
        assert!(matches!(
            err,
            Error::Verification {
                code: ErrorCode::BundleUnsigned,
                ..
            }
        ));
    }

    #[test]
    fn test_expired_bundle_rejected() {
        let kp = generate_key_pair().unwrap();
        let bundle = make_bundle("example.com", "2020-01-01T00:00:00Z");
        let signed = sign_trust_bundle(
            &bundle,
            &kp.private_key_pem,
            "auth",
            "2020-01-01T00:00:00Z",
            Some("2020-02-01T00:00:00Z"),
        )
        .unwrap();
        let mut store = KeyPinStore::new();
        let err = verify_trust_bundle(&signed, &mut store).unwrap_err();
        assert!(matches!(
            err,
            Error::Verification {
                code: ErrorCode::BundleExpired,
                ..
            }
        ));
    }

    #[test]
    fn test_authority_tofu_mismatch() {
        let kp1 = generate_key_pair().unwrap();
        let kp2 = generate_key_pair().unwrap();
        let bundle = make_bundle("example.com", "2026-05-15T00:00:00Z");

        let signed1 = sign_trust_bundle(
            &bundle,
            &kp1.private_key_pem,
            "auth",
            "2026-05-15T00:00:00Z",
            None,
        )
        .unwrap();
        // Different key, SAME kid → impersonation attempt.
        let signed2 = sign_trust_bundle(
            &bundle,
            &kp2.private_key_pem,
            "auth",
            "2026-05-16T00:00:00Z",
            None,
        )
        .unwrap();

        let mut store = KeyPinStore::new();
        verify_trust_bundle(&signed1, &mut store).unwrap(); // pins kp1
        let err = verify_trust_bundle(&signed2, &mut store).unwrap_err();
        assert!(matches!(
            err,
            Error::Verification {
                code: ErrorCode::KeyPinMismatch,
                ..
            }
        ));
    }

    #[test]
    fn test_merge_newest_wins() {
        let mut older = make_bundle("example.com", "2026-01-01T00:00:00Z");
        older.documents[0].well_known.developer_name = Some("Old".to_string());
        let mut newer = make_bundle("example.com", "2026-05-01T00:00:00Z");
        newer.documents[0].well_known.developer_name = Some("New".to_string());
        let other = make_bundle("other.com", "2026-03-01T00:00:00Z");

        let merged = merge_trust_bundles(&[older, newer, other]);
        assert_eq!(merged.documents.len(), 2);
        let ex = merged
            .documents
            .iter()
            .find(|d| d.domain == "example.com")
            .unwrap();
        assert_eq!(ex.well_known.developer_name.as_deref(), Some("New"));
        assert_eq!(merged.created_at, "2026-05-01T00:00:00Z");
    }

    #[test]
    fn test_merge_signed_at_beats_created_at() {
        // A bundle signed later (signed_at) should win even if created_at is older.
        let mut a = make_bundle("example.com", "2026-01-01T00:00:00Z");
        a.signed_at = Some("2026-09-01T00:00:00Z".to_string());
        a.documents[0].well_known.developer_name = Some("Signed-late".to_string());
        let mut b = make_bundle("example.com", "2026-06-01T00:00:00Z");
        b.documents[0].well_known.developer_name = Some("Created-mid".to_string());

        let merged = merge_trust_bundles(&[b, a]);
        let ex = &merged.documents[0];
        assert_eq!(ex.well_known.developer_name.as_deref(), Some("Signed-late"));
    }

    #[test]
    fn test_jsonrpc_envelope_roundtrip() {
        let kp = generate_key_pair().unwrap();
        let bundle = make_bundle("example.com", "2026-05-15T00:00:00Z");
        let signed = sign_trust_bundle(
            &bundle,
            &kp.private_key_pem,
            "auth",
            "2026-05-15T00:00:00Z",
            None,
        )
        .unwrap();

        let req = build_trust_bundle_request(Some("example.com"), json!(1));
        assert_eq!(req["method"], "schemapin/trustBundle");
        assert_eq!(req["params"]["domain"], "example.com");

        let resp = build_trust_bundle_response(&signed, json!(1)).unwrap();
        let parsed = parse_trust_bundle_response(&resp).unwrap();
        assert_eq!(parsed, signed);

        // And the parsed bundle still verifies.
        let mut store = KeyPinStore::new();
        verify_trust_bundle(&parsed, &mut store).unwrap();
    }
}
