#![no_main]
use libfuzzer_sys::fuzz_target;
use schemapin::bundle::{merge_trust_bundles, verify_trust_bundle_with_options, BundleVerifyOptions};
use schemapin::pinning::KeyPinStore;
use schemapin::types::bundle::SchemaPinTrustBundle;

fuzz_target!(|data: &[u8]| {
    if let Ok(bundle) = serde_json::from_slice::<SchemaPinTrustBundle>(data) {
        let mut store = KeyPinStore::new();
        let _ = verify_trust_bundle_with_options(
            &bundle,
            &mut store,
            &BundleVerifyOptions { allow_first_use: true },
        );
        let _ = merge_trust_bundles(&[bundle.clone(), bundle]);
    }
});
