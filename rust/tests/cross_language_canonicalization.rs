//! Cross-language conformance: canonicalization corpus shared by all SDKs
//! (see ../../tests/cross-language/README.md).

use schemapin::canonicalize::{canonicalize_schema, parse_schema_json};
use sha2::{Digest, Sha256};

#[derive(serde::Deserialize)]
struct Vector {
    name: String,
    input: String,
    reject: bool,
    #[serde(default)]
    expected_canonical: Option<String>,
    #[serde(default)]
    expected_sha256: Option<String>,
}

#[test]
fn cross_language_canonicalization_corpus() {
    let dir = std::path::Path::new("../tests/cross-language/canonicalization");
    let mut paths: Vec<_> = std::fs::read_dir(dir)
        .expect("corpus directory present")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "corpus must not be empty");

    for path in paths {
        let text = std::fs::read_to_string(&path).unwrap();
        let v: Vector = serde_json::from_str(&text).unwrap();
        let result = parse_schema_json(&v.input).and_then(|val| canonicalize_schema(&val));
        if v.reject {
            assert!(
                result.is_err(),
                "{}: expected rejection, got {:?}",
                v.name,
                result
            );
            continue;
        }
        let canonical = result.unwrap_or_else(|e| panic!("{}: {}", v.name, e));
        assert_eq!(
            canonical,
            v.expected_canonical.clone().unwrap(),
            "{}: canonical mismatch",
            v.name
        );
        let digest = hex::encode(Sha256::digest(canonical.as_bytes()));
        assert_eq!(
            digest,
            v.expected_sha256.unwrap(),
            "{}: sha256 mismatch",
            v.name
        );
        let again = canonicalize_schema(&parse_schema_json(&canonical).unwrap()).unwrap();
        assert_eq!(again, canonical, "{}: not idempotent", v.name);
    }
}
