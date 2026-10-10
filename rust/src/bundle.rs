//! (v1.4) Trust-bundle distribution for A2A networks.
//!
//! Lets a *bundle authority* sign a [`SchemaPinTrustBundle`] so it can be
//! exchanged between agents over A2A without per-bundle out-of-band trust
//! establishment. Provides:
//!
//! - [`sign_trust_bundle`] / [`verify_trust_bundle`] — ECDSA P-256 over the
//!   canonical bundle bytes, with an **authority allow-list**: the authority
//!   key must be pre-seeded in the authority store ([`seed_bundle_authority`])
//!   unless the caller explicitly opts in to first-use trust.
//! - [`merge_trust_bundles`] — combine bundles from multiple sources with
//!   per-authority precedence and parsed-timestamp tie-breaking.
//! - [`build_trust_bundle_request`] / [`build_trust_bundle_response`] /
//!   [`parse_trust_bundle_response`] — the `schemapin/trustBundle` JSON-RPC
//!   envelope for A2A bundle exchange.
//!
//! ## Signing input
//!
//! The signature covers the `schemapin-v1` canonicalization of the bundle's
//! known fields (the serde representation; unknown fields are dropped on parse
//! and therefore unprotected) with the `signature` field set to `""`. All
//! four SDKs build the identical byte string, so a bundle signed by any SDK
//! verifies in every other.

use serde_json::{json, Value};

use crate::canonicalize::canonicalize_schema;
use crate::crypto::{calculate_key_id, sign_data, verify_signature, KeyManager};
use crate::error::{Error, ErrorCode};
use crate::pinning::{KeyPinStore, PinningResult};
use crate::types::bundle::{BundleAuthority, SchemaPinTrustBundle};
use crate::verification::parse_rfc3339_strict;

/// Successful [`verify_trust_bundle_with_options`] outcome. `first_use` is
/// `true` when the authority key was not pre-seeded and the caller allowed
/// first-use trust; hosts should surface this exactly like a first-use tool key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleVerification {
    pub kid: String,
    pub fingerprint: String,
    pub first_use: bool,
}

/// Policy knobs for [`verify_trust_bundle_with_options`].
#[derive(Debug, Clone, Copy, Default)]
pub struct BundleVerifyOptions {
    /// Pin an unknown authority on first use (TOFU) instead of failing with
    /// `BUNDLE_AUTHORITY_UNTRUSTED`.
    pub allow_first_use: bool,
}

/// Pre-seed the expected fingerprint (`sha256:<hex>`) of a bundle authority.
/// This is the allow-list entry [`verify_trust_bundle`] requires.
pub fn seed_bundle_authority(store: &mut KeyPinStore, kid: &str, fingerprint: &str) {
    store.seed(kid, BUNDLE_AUTHORITY_PIN_DOMAIN, fingerprint);
}

/// Seed an authority from its PEM public key (for example the
/// `public_key_pem` of the authority's own discovery document). Returns the
/// fingerprint.
pub fn seed_bundle_authority_from_pem(
    store: &mut KeyPinStore,
    kid: &str,
    public_key_pem: &str,
) -> Result<String, Error> {
    let fingerprint = calculate_key_id(public_key_pem)?;
    seed_bundle_authority(store, kid, &fingerprint);
    Ok(fingerprint)
}

/// Return a domain that appears more than once in the bundle's documents or
/// revocations.
pub fn duplicate_domain(bundle: &SchemaPinTrustBundle) -> Option<String> {
    let mut seen = std::collections::HashSet::new();
    for d in &bundle.documents {
        if !seen.insert(d.domain.as_str()) {
            return Some(d.domain.clone());
        }
    }
    let mut seen = std::collections::HashSet::new();
    for r in &bundle.revocations {
        if !seen.insert(r.domain.as_str()) {
            return Some(r.domain.clone());
        }
    }
    None
}

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
    canonicalize_schema(&value)
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
    if let Some(dup) = duplicate_domain(bundle) {
        return Err(Error::Verification {
            code: ErrorCode::DiscoveryInvalid,
            message: format!("trust bundle has duplicate entries for domain {:?}", dup),
        });
    }
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

/// Verify a signed trust bundle against the authority allow-list: the
/// authority `kid` must already be seeded in `authority_pin_store`
/// ([`seed_bundle_authority`]) or verification fails with
/// `BUNDLE_AUTHORITY_UNTRUSTED`. Use [`verify_trust_bundle_with_options`] to
/// allow first-use pinning.
pub fn verify_trust_bundle(
    bundle: &SchemaPinTrustBundle,
    authority_pin_store: &mut KeyPinStore,
) -> Result<(), Error> {
    verify_trust_bundle_with_options(bundle, authority_pin_store, &BundleVerifyOptions::default())
        .map(|_| ())
}

/// Verify a signed trust bundle.
///
/// Steps: require `bundle_authority` + `signature` (`BUNDLE_UNSIGNED`);
/// reject duplicate domains (`DISCOVERY_INVALID`); reject when `expires_at`
/// is in the past or not strict RFC 3339 (`BUNDLE_EXPIRED`); look the
/// authority's key fingerprint up by `kid` — a different pinned key is
/// `KEY_PIN_MISMATCH`, an unknown `kid` is `BUNDLE_AUTHORITY_UNTRUSTED`
/// unless `opts.allow_first_use`; verify the signature over the canonical
/// bytes (`SIGNATURE_INVALID`); pin the authority on first use only after the
/// signature verified.
///
/// The bundle carries its own public key, so without an allow-list any
/// self-signed bundle under a fresh `kid` would pass. Treat `allow_first_use`
/// exactly like TOFU for a tool key (prompt the user, log it).
pub fn verify_trust_bundle_with_options(
    bundle: &SchemaPinTrustBundle,
    authority_pin_store: &mut KeyPinStore,
    opts: &BundleVerifyOptions,
) -> Result<BundleVerification, Error> {
    let authority = bundle
        .bundle_authority
        .as_ref()
        .ok_or(Error::Verification {
            code: ErrorCode::BundleUnsigned,
            message: "trust bundle has no bundle_authority".to_string(),
        })?;
    let signature = bundle.signature.as_ref().ok_or(Error::Verification {
        code: ErrorCode::BundleUnsigned,
        message: "trust bundle has no signature".to_string(),
    })?;

    if let Some(dup) = duplicate_domain(bundle) {
        return Err(Error::Verification {
            code: ErrorCode::DiscoveryInvalid,
            message: format!("trust bundle has duplicate entries for domain {:?}", dup),
        });
    }

    if let Some(expires_at) = &bundle.expires_at {
        let exp = parse_rfc3339_strict(expires_at).ok_or_else(|| Error::Verification {
            code: ErrorCode::BundleExpired,
            message: format!("unparseable expires_at '{}'", expires_at),
        })?;
        if chrono::Utc::now() > exp {
            return Err(Error::Verification {
                code: ErrorCode::BundleExpired,
                message: format!("trust bundle expired at {}", expires_at),
            });
        }
    }

    let fingerprint =
        calculate_key_id(&authority.public_key_pem).map_err(|e| Error::Verification {
            code: ErrorCode::KeyNotFound,
            message: format!("bundle authority key is invalid: {}", e),
        })?;
    let pin_result =
        authority_pin_store.check(&authority.kid, BUNDLE_AUTHORITY_PIN_DOMAIN, &fingerprint);
    match pin_result {
        PinningResult::Changed => {
            return Err(Error::Verification {
                code: ErrorCode::KeyPinMismatch,
                message: format!(
                    "bundle authority key for kid '{}' does not match the seeded authority key",
                    authority.kid
                ),
            });
        }
        PinningResult::FirstUse if !opts.allow_first_use => {
            return Err(Error::Verification {
                code: ErrorCode::BundleAuthorityUntrusted,
                message: format!(
                    "bundle authority kid '{}' is not in the authority allow-list; seed it with seed_bundle_authority or set allow_first_use",
                    authority.kid
                ),
            });
        }
        _ => {}
    }

    let canonical = signing_bytes(bundle)?;
    if !verify_signature(&authority.public_key_pem, canonical.as_bytes(), signature)? {
        return Err(Error::Verification {
            code: ErrorCode::SignatureInvalid,
            message: "trust bundle signature does not verify".to_string(),
        });
    }
    if pin_result == PinningResult::FirstUse {
        authority_pin_store.pin(&authority.kid, BUNDLE_AUTHORITY_PIN_DOMAIN, &fingerprint);
    }
    Ok(BundleVerification {
        kid: authority.kid.clone(),
        fingerprint,
        first_use: pin_result == PinningResult::FirstUse,
    })
}

/// Rank used by [`merge_trust_bundles_with_precedence`]: higher wins.
fn merge_rank(
    bundle: &SchemaPinTrustBundle,
    precedence: Option<&[&str]>,
) -> (i64, chrono::DateTime<chrono::Utc>) {
    let mut rank: i64 = 0;
    if let Some(list) = precedence {
        if !list.is_empty() {
            rank = -(list.len() as i64) - 1;
            if let Some(auth) = &bundle.bundle_authority {
                if let Some(i) = list.iter().position(|k| *k == auth.kid) {
                    rank = -(i as i64);
                }
            }
        }
    }
    let raw = bundle.signed_at.as_deref().unwrap_or(&bundle.created_at);
    let ts = parse_rfc3339_strict(raw).unwrap_or(chrono::DateTime::<chrono::Utc>::MIN_UTC);
    (rank, ts)
}

/// Merge trust bundles, deduplicating discovery + revocation documents by
/// domain. When two bundles carry the same domain, the entry from the bundle
/// with the newer **parsed** timestamp (`signed_at`, else `created_at`) wins;
/// unparseable timestamps rank oldest. Equivalent to
/// [`merge_trust_bundles_with_precedence`] with no precedence list.
pub fn merge_trust_bundles(bundles: &[SchemaPinTrustBundle]) -> SchemaPinTrustBundle {
    merge_trust_bundles_with_precedence(bundles, None)
}

/// [`merge_trust_bundles`] with per-authority precedence: `authority_precedence`
/// lists authority `kid`s, earlier wins; bundles from unlisted or absent
/// authorities rank last; the parsed timestamp breaks ties. Merge only
/// bundles you have already verified with [`verify_trust_bundle`].
///
/// The result is an *unsigned* bundle stamped `schemapin_bundle_version =
/// "1.4"` with `created_at` set to the newest source timestamp. Re-sign it
/// with [`sign_trust_bundle`] before redistribution.
pub fn merge_trust_bundles_with_precedence(
    bundles: &[SchemaPinTrustBundle],
    authority_precedence: Option<&[&str]>,
) -> SchemaPinTrustBundle {
    use std::collections::HashMap;

    type Rank = (i64, chrono::DateTime<chrono::Utc>);
    let mut docs: HashMap<String, (Rank, _)> = HashMap::new();
    let mut revs: HashMap<String, (Rank, _)> = HashMap::new();
    let mut newest: Option<chrono::DateTime<chrono::Utc>> = None;
    let mut newest_raw = String::new();

    for b in bundles {
        let rank = merge_rank(b, authority_precedence);
        if newest.is_none_or(|n| rank.1 > n) {
            newest = Some(rank.1);
            newest_raw = b.signed_at.clone().unwrap_or_else(|| b.created_at.clone());
        }
        for d in &b.documents {
            match docs.get(&d.domain) {
                Some((existing, _)) if *existing >= rank => {}
                _ => {
                    docs.insert(d.domain.clone(), (rank, d.clone()));
                }
            }
        }
        for r in &b.revocations {
            match revs.get(&r.domain) {
                Some((existing, _)) if *existing >= rank => {}
                _ => {
                    revs.insert(r.domain.clone(), (rank, r.clone()));
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
        created_at: newest_raw,
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
    let bundle =
        response
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

    fn verify_first_use(
        bundle: &SchemaPinTrustBundle,
        store: &mut KeyPinStore,
    ) -> Result<(), Error> {
        verify_trust_bundle_with_options(
            bundle,
            store,
            &BundleVerifyOptions {
                allow_first_use: true,
            },
        )
        .map(|_| ())
    }

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
        assert_eq!(
            signed.bundle_authority.as_ref().unwrap().kid,
            "auth-2026-05"
        );

        let mut store = KeyPinStore::new();
        verify_first_use(&signed, &mut store).unwrap();
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
        let err = verify_first_use(&signed, &mut store).unwrap_err();
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
        let err = verify_first_use(&bundle, &mut store).unwrap_err();
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
        let err = verify_first_use(&signed, &mut store).unwrap_err();
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
        verify_first_use(&signed1, &mut store).unwrap(); // pins kp1
        let err = verify_first_use(&signed2, &mut store).unwrap_err();
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
        verify_first_use(&parsed, &mut store).unwrap();
    }

    // ── authority allow-list (SP-6), parity (SP-19), merge precedence ──

    #[test]
    fn test_authority_allow_list() {
        let kp = generate_key_pair().unwrap();
        let signed = sign_trust_bundle(
            &make_bundle("victim.com", "2026-05-15T00:00:00Z"),
            &kp.private_key_pem,
            "victim-authority-2026",
            "2026-05-15T00:00:00Z",
            None,
        )
        .unwrap();
        let mut empty = KeyPinStore::new();
        match verify_trust_bundle(&signed, &mut empty).unwrap_err() {
            Error::Verification { code, .. } => {
                assert_eq!(code, ErrorCode::BundleAuthorityUntrusted)
            }
            e => panic!("unexpected error {:?}", e),
        }

        let mut store = KeyPinStore::new();
        let fp = seed_bundle_authority_from_pem(
            &mut store,
            "victim-authority-2026",
            &signed.bundle_authority.as_ref().unwrap().public_key_pem,
        )
        .unwrap();
        let res =
            verify_trust_bundle_with_options(&signed, &mut store, &BundleVerifyOptions::default())
                .unwrap();
        assert!(!res.first_use);
        assert_eq!(res.fingerprint, fp);

        let mut fresh = KeyPinStore::new();
        let res = verify_trust_bundle_with_options(
            &signed,
            &mut fresh,
            &BundleVerifyOptions {
                allow_first_use: true,
            },
        )
        .unwrap();
        assert!(res.first_use);
        assert!(verify_trust_bundle(&signed, &mut fresh).is_ok());

        // A failed signature never pins.
        let mut tampered = sign_trust_bundle(
            &make_bundle("example.com", "2026-05-15T00:00:00Z"),
            &kp.private_key_pem,
            "auth",
            "2026-05-15T00:00:00Z",
            None,
        )
        .unwrap();
        tampered.documents[0].domain = "evil.com".to_string();
        let mut s2 = KeyPinStore::new();
        assert!(verify_first_use(&tampered, &mut s2).is_err());
        assert!(s2.get_tool("auth", BUNDLE_AUTHORITY_PIN_DOMAIN).is_none());
    }

    #[test]
    fn test_strict_expires_at_and_duplicates() {
        let kp = generate_key_pair().unwrap();
        for bad in ["2099-01-01", "2099-01-01T00:00:00", "2099-01-01 00:00:00Z"] {
            let signed = sign_trust_bundle(
                &make_bundle("example.com", "2026-05-15T00:00:00Z"),
                &kp.private_key_pem,
                "auth",
                "2026-05-15T00:00:00Z",
                Some(bad),
            )
            .unwrap();
            match verify_first_use(&signed, &mut KeyPinStore::new()).unwrap_err() {
                Error::Verification { code, .. } => {
                    assert_eq!(code, ErrorCode::BundleExpired, "{}", bad)
                }
                e => panic!("unexpected error {:?}", e),
            }
        }
        let mut dup = make_bundle("example.com", "2026-05-15T00:00:00Z");
        dup.documents.push(dup.documents[0].clone());
        assert!(sign_trust_bundle(
            &dup,
            &kp.private_key_pem,
            "auth",
            "2026-05-15T00:00:00Z",
            None
        )
        .is_err());
        assert!(crate::resolver::TrustBundleResolver::from_json(
            &serde_json::to_string(&dup).unwrap()
        )
        .is_err());
    }

    #[test]
    fn test_merge_precedence() {
        let trusted = generate_key_pair().unwrap();
        let rogue = generate_key_pair().unwrap();
        let named = |name: &str, ts: &str| {
            let mut b = make_bundle("example.com", ts);
            b.documents[0].well_known.developer_name = Some(name.to_string());
            b
        };
        let good = sign_trust_bundle(
            &named("Good", "2026-01-01T00:00:00Z"),
            &trusted.private_key_pem,
            "trusted",
            "2026-01-01T00:00:00Z",
            None,
        )
        .unwrap();
        let bad = sign_trust_bundle(
            &named("Rogue", "2099-01-01T00:00:00Z"),
            &rogue.private_key_pem,
            "rogue",
            "2099-01-01T00:00:00Z",
            None,
        )
        .unwrap();
        let merged =
            merge_trust_bundles_with_precedence(&[bad.clone(), good.clone()], Some(&["trusted"]));
        assert_eq!(
            merged.documents[0].well_known.developer_name.as_deref(),
            Some("Good")
        );
        let merged = merge_trust_bundles(&[good, bad]);
        assert_eq!(
            merged.documents[0].well_known.developer_name.as_deref(),
            Some("Rogue")
        );
        let real = named("Real", "2026-01-01T00:00:00Z");
        let bogus = named("Bogus", "9999-99-99 bogus");
        assert_eq!(
            merge_trust_bundles(&[real.clone(), bogus]).documents[0]
                .well_known
                .developer_name
                .as_deref(),
            Some("Real")
        );
        let offset = named("Offset", "2026-02-01T00:00:00+00:00");
        assert_eq!(
            merge_trust_bundles(&[real, offset]).documents[0]
                .well_known
                .developer_name
                .as_deref(),
            Some("Offset")
        );
    }
}
