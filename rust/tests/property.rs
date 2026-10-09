//! Property-based tests (proptest) for the parsers that face untrusted input.

use proptest::prelude::*;
use schemapin::canonicalize::{canonicalize_schema, parse_schema_json, MAX_SAFE_INTEGER};
use schemapin::dns::parse_txt_record;
use schemapin::domain::validate_domain;
use serde_json::Value;

fn json_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        (-(MAX_SAFE_INTEGER as i64)..=(MAX_SAFE_INTEGER as i64)).prop_map(Value::from),
        (-1e15f64..1e15f64).prop_map(|f| serde_json::Number::from_f64(f)
            .map(Value::Number)
            .unwrap_or(Value::Null)),
        ".*".prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 40, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::btree_map(".*", inner, 0..6)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    #[test]
    fn canonicalization_is_idempotent(value in json_value()) {
        let c1 = canonicalize_schema(&value).unwrap();
        let again = parse_schema_json(&c1).unwrap();
        prop_assert_eq!(canonicalize_schema(&again).unwrap(), c1.clone());
        prop_assert_eq!(serde_json::from_str::<Value>(&c1).unwrap(), again);
    }

    #[test]
    fn strict_parser_never_panics(text in ".*") {
        if let Ok(v) = parse_schema_json(&text) {
            let _ = canonicalize_schema(&v);
        }
    }

    #[test]
    fn txt_parser_never_panics(text in ".*") {
        if let Ok(rec) = parse_txt_record(&text) {
            prop_assert!(rec.fingerprint.starts_with("sha256:"));
        }
    }

    #[test]
    fn domain_validator_is_idempotent(text in ".*") {
        if let Ok(n) = validate_domain(&text) {
            prop_assert_eq!(validate_domain(&n).unwrap(), n);
        }
    }
}
