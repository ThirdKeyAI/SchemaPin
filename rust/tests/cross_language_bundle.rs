//! Cross-language interop: verify the shared signed-bundle fixture that every
//! SDK checks (see ../../tests/cross-language/README.md).

use schemapin::bundle::{
    seed_bundle_authority, seed_bundle_authority_from_pem, verify_trust_bundle,
    verify_trust_bundle_with_options, BundleVerifyOptions, BUNDLE_AUTHORITY_PIN_DOMAIN,
};
use schemapin::error::{Error, ErrorCode};
use schemapin::pinning::KeyPinStore;
use schemapin::types::bundle::SchemaPinTrustBundle;

fn fixture() -> SchemaPinTrustBundle {
    let json = std::fs::read_to_string("../tests/cross-language/signed_bundle.json")
        .expect("fixture present");
    serde_json::from_str(&json).unwrap()
}

#[test]
fn verifies_shared_signed_bundle_fixture_once_seeded() {
    let bundle = fixture();
    let kid = bundle.bundle_authority.as_ref().unwrap().kid.clone();
    assert_eq!(kid, "schemapin-test-fixture-authority");

    // Unknown authority: refused unless seeded.
    match verify_trust_bundle(&bundle, &mut KeyPinStore::new()).unwrap_err() {
        Error::Verification { code, .. } => assert_eq!(code, ErrorCode::BundleAuthorityUntrusted),
        e => panic!("unexpected error {:?}", e),
    }

    let pub_pem =
        std::fs::read_to_string("../tests/cross-language/keys/test-only-bundle-authority.pub.pem")
            .unwrap();
    let mut store = KeyPinStore::new();
    seed_bundle_authority_from_pem(&mut store, &kid, &pub_pem).unwrap();
    let res =
        verify_trust_bundle_with_options(&bundle, &mut store, &BundleVerifyOptions::default())
            .expect("shared fixture must verify");
    assert!(!res.first_use);

    // A different seeded key is an impersonation.
    let mut other = KeyPinStore::new();
    seed_bundle_authority(&mut other, &kid, &format!("sha256:{}", "00".repeat(32)));
    match verify_trust_bundle(&bundle, &mut other).unwrap_err() {
        Error::Verification { code, .. } => assert_eq!(code, ErrorCode::KeyPinMismatch),
        e => panic!("unexpected error {:?}", e),
    }
    let _ = BUNDLE_AUTHORITY_PIN_DOMAIN;
}
