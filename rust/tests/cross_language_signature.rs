//! Cross-language interop: fixed ECDSA signature vector and key-policy
//! fixtures shared by every SDK (see ../../tests/cross-language/README.md).

use schemapin::canonicalize::{canonicalize_and_hash, canonicalize_schema, hash_canonical};
use schemapin::crypto::{calculate_key_id, verify_signature};
use serde_json::Value;

#[derive(serde::Deserialize)]
struct Vector {
    public_key_pem: String,
    key_fingerprint: String,
    schema: Value,
    canonical: String,
    sha256: String,
    signature: String,
    signature_with_trailing_byte: String,
    tampered_schema: Value,
}

fn load_vector() -> Vector {
    let text = std::fs::read_to_string("../tests/cross-language/signatures/schema-signature.json")
        .expect("fixture present");
    serde_json::from_str(&text).unwrap()
}

#[test]
fn fixed_schema_signature_verifies() {
    let v = load_vector();
    let canonical = canonicalize_schema(&v.schema).unwrap();
    assert_eq!(canonical, v.canonical);
    let digest = hash_canonical(&canonical);
    assert_eq!(hex::encode(&digest), v.sha256);
    assert_eq!(
        calculate_key_id(&v.public_key_pem).unwrap(),
        v.key_fingerprint
    );
    assert!(verify_signature(&v.public_key_pem, &digest, &v.signature).unwrap());
}

#[test]
fn tampered_schema_and_trailing_der_bytes_rejected() {
    let v = load_vector();
    let digest = hash_canonical(&v.canonical);
    let tampered = canonicalize_and_hash(&v.tampered_schema).unwrap();
    assert!(!verify_signature(&v.public_key_pem, &tampered, &v.signature).unwrap());
    let trailing = verify_signature(&v.public_key_pem, &digest, &v.signature_with_trailing_byte);
    assert!(matches!(trailing, Ok(false) | Err(_)));
}

#[test]
fn non_p256_public_keys_rejected() {
    for name in ["reject-p384-public.pem", "reject-rsa2048-public.pem"] {
        let pem =
            std::fs::read_to_string(format!("../tests/cross-language/keys/{}", name)).unwrap();
        assert!(calculate_key_id(&pem).is_err(), "{} must be rejected", name);
        assert!(
            verify_signature(&pem, b"x", "AAAA").is_err(),
            "{} must be rejected",
            name
        );
    }
}
