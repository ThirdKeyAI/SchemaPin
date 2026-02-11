use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Recursively sort JSON object keys and produce a canonical string.
///
/// - Object keys are sorted lexicographically (BTreeMap guarantees this).
/// - Arrays preserve element order.
/// - All insignificant whitespace is removed.
pub fn canonicalize_schema(schema: &Value) -> String {
    let sorted = sort_keys_recursive(schema);
    serde_json::to_string(&sorted).unwrap_or_default()
}

/// SHA-256 hash of a canonical string, returned as raw bytes.
pub fn hash_canonical(canonical: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hasher.finalize().to_vec()
}

/// Canonicalize a schema and return its SHA-256 hash.
pub fn canonicalize_and_hash(schema: &Value) -> Vec<u8> {
    let canonical = canonicalize_schema(schema);
    hash_canonical(&canonical)
}

/// Recursively sort all object keys, producing a new Value.
fn sort_keys_recursive(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted: BTreeMap<String, Value> = map
                .iter()
                .map(|(k, v)| (k.clone(), sort_keys_recursive(v)))
                .collect();
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(arr) => Value::Array(arr.iter().map(sort_keys_recursive).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_spec_example_canonicalization() {
        let schema = json!({
            "description": "Calculates the sum",
            "name": "calculate_sum",
            "parameters": { "b": "integer", "a": "integer" }
        });
        let canonical = canonicalize_schema(&schema);
        assert_eq!(
            canonical,
            r#"{"description":"Calculates the sum","name":"calculate_sum","parameters":{"a":"integer","b":"integer"}}"#
        );
    }

    #[test]
    fn test_nested_objects_sorted() {
        let schema = json!({
            "z": { "b": 2, "a": 1 },
            "a": { "d": 4, "c": 3 }
        });
        let canonical = canonicalize_schema(&schema);
        assert_eq!(canonical, r#"{"a":{"c":3,"d":4},"z":{"a":1,"b":2}}"#);
    }

    #[test]
    fn test_arrays_preserve_order() {
        let schema = json!({
            "items": [3, 1, 2],
            "name": "test"
        });
        let canonical = canonicalize_schema(&schema);
        assert_eq!(canonical, r#"{"items":[3,1,2],"name":"test"}"#);
    }

    #[test]
    fn test_deterministic_hash() {
        let schema = json!({
            "name": "calculate_sum",
            "description": "Calculates the sum",
            "parameters": { "b": "integer", "a": "integer" }
        });
        let hash1 = canonicalize_and_hash(&schema);
        let hash2 = canonicalize_and_hash(&schema);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32); // SHA-256 = 32 bytes
    }

    #[test]
    fn test_key_order_independence() {
        let schema_a = json!({"z": 1, "a": 2, "m": 3});
        let schema_b = json!({"a": 2, "m": 3, "z": 1});
        assert_eq!(
            canonicalize_schema(&schema_a),
            canonicalize_schema(&schema_b)
        );
    }

    #[test]
    fn test_hash_canonical_output() {
        let canonical = r#"{"name":"test"}"#;
        let hash = hash_canonical(canonical);
        assert_eq!(hash.len(), 32);
        // Verify it's the expected SHA-256 (deterministic)
        let hash2 = hash_canonical(canonical);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_deeply_nested_sorting() {
        let schema = json!({
            "level1": {
                "level2": {
                    "z": "last",
                    "a": "first"
                }
            }
        });
        let canonical = canonicalize_schema(&schema);
        assert_eq!(
            canonical,
            r#"{"level1":{"level2":{"a":"first","z":"last"}}}"#
        );
    }
}
