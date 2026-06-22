//! Cross-language interop: verify the shared signed-bundle fixture that every
//! SDK checks (see ../../tests/cross-language/README.md).

use schemapin::bundle::verify_trust_bundle;
use schemapin::pinning::KeyPinStore;
use schemapin::types::bundle::SchemaPinTrustBundle;

#[test]
fn verifies_shared_signed_bundle_fixture() {
    let json = std::fs::read_to_string("../tests/cross-language/signed_bundle.json")
        .expect("fixture present");
    let bundle: SchemaPinTrustBundle = serde_json::from_str(&json).unwrap();
    let mut store = KeyPinStore::new();
    verify_trust_bundle(&bundle, &mut store).expect("shared fixture must verify");
}
