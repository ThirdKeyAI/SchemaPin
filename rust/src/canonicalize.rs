//! `schemapin-v1` canonical JSON serialization.
//!
//! Implements TECHNICAL_SPECIFICATION.md section 4. The rules are strict so
//! that every SDK produces byte-identical output:
//!
//! - Object keys are sorted by Unicode code point (bytewise order of their
//!   UTF-8 encoding).
//! - Duplicate object keys, `NaN`/`Infinity`, lone surrogates and invalid
//!   UTF-8 are rejected -- they have no canonical form.
//! - Strings are escaped minimally: `"` and `\` are backslash-escaped,
//!   U+0008/U+000C/U+000A/U+000D/U+0009 use `\b \f \n \r \t`, the remaining
//!   C0 controls use lowercase `\u00xx`, and everything else (including `<`,
//!   `>`, `&`, U+007F, U+2028 and U+2029) is emitted literally.
//! - Numbers are IEEE-754 binary64. Any value whose magnitude exceeds
//!   2^53 - 1 is rejected. Integral values are emitted as plain decimal
//!   integers (`-0` -> `0`); non-integral values use ECMAScript
//!   `Number::toString` (RFC 8785 section 3.2.2.3).

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::fmt;

use crate::error::Error;

/// Canonical-algorithm identifier (v1.4) for the sorted-key, no-whitespace,
/// UTF-8 canonicalization implemented in this module.
///
/// Signatures MAY carry a `canonicalization` field naming the algorithm used
/// to produce the signing input. Absence is equivalent to this identifier
/// for backward compatibility with v1.3 signatures. Verifiers MUST reject
/// any other value as `CANONICALIZATION_UNSUPPORTED`.
pub const CANONICALIZATION_V1: &str = "schemapin-v1";

/// Largest integer magnitude accepted by the canonicalizer (2^53 - 1).
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

const MAX_DEPTH: usize = 512;

/// Returns `Ok(())` if `algorithm` names a canonicalization algorithm this
/// SDK supports. Returns `Err(declared)` with the offending value when it
/// does not — the caller surfaces this as `ErrorCode::CanonicalizationUnsupported`.
///
/// `None` means the field is absent and is equivalent to the default
/// `schemapin-v1` algorithm (v1.3 backward compatibility).
pub fn check_canonicalization(algorithm: Option<&str>) -> Result<(), String> {
    match algorithm {
        None | Some(CANONICALIZATION_V1) => Ok(()),
        Some(other) => Err(other.to_string()),
    }
}

fn canon_err(msg: impl Into<String>) -> Error {
    Error::Canonicalization(msg.into())
}

/// Produce the `schemapin-v1` canonical string for a JSON value.
///
/// Fails when the value has no canonical form (numbers outside the 2^53 - 1
/// safe range; `serde_json::Value` cannot hold NaN, duplicates or invalid
/// UTF-8, so those are rejected by [`parse_schema_json`] instead).
pub fn canonicalize_schema(schema: &Value) -> Result<String, Error> {
    let mut out = String::new();
    write_value(&mut out, schema, 0)?;
    Ok(out)
}

/// SHA-256 hash of a canonical string, returned as raw bytes.
pub fn hash_canonical(canonical: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hasher.finalize().to_vec()
}

/// Canonicalize a schema and return its SHA-256 hash.
pub fn canonicalize_and_hash(schema: &Value) -> Result<Vec<u8>, Error> {
    let canonical = canonicalize_schema(schema)?;
    Ok(hash_canonical(&canonical))
}

fn write_value(out: &mut String, value: &Value, depth: usize) -> Result<(), Error> {
    if depth > MAX_DEPTH {
        return Err(canon_err("nesting depth exceeds limit"));
    }
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::String(s) => write_string(out, s),
        Value::Number(n) => write_number(out, n)?,
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item, depth + 1)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort(); // String ordering is bytewise == code point order
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, key);
                out.push(':');
                write_value(out, &map[*key], depth + 1)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_number(out: &mut String, n: &Number) -> Result<(), Error> {
    if let Some(i) = n.as_i64() {
        if i.unsigned_abs() > MAX_SAFE_INTEGER {
            return Err(canon_err(format!(
                "integer {} exceeds the 2^53-1 safe range",
                i
            )));
        }
        out.push_str(&i.to_string());
        return Ok(());
    }
    if let Some(u) = n.as_u64() {
        if u > MAX_SAFE_INTEGER {
            return Err(canon_err(format!(
                "integer {} exceeds the 2^53-1 safe range",
                u
            )));
        }
        out.push_str(&u.to_string());
        return Ok(());
    }
    let f = n
        .as_f64()
        .ok_or_else(|| canon_err("unrepresentable number"))?;
    write_f64(out, f)
}

fn write_f64(out: &mut String, f: f64) -> Result<(), Error> {
    if !f.is_finite() {
        return Err(canon_err("NaN and Infinity are not valid JSON"));
    }
    if f.abs() > MAX_SAFE_INTEGER as f64 {
        return Err(canon_err(format!(
            "number {} exceeds the 2^53-1 safe range",
            f
        )));
    }
    if f.fract() == 0.0 {
        // Exact for |f| <= 2^53 - 1; also maps -0.0 to "0".
        out.push_str(&(f as i64).to_string());
        return Ok(());
    }
    out.push_str(&es6_number_to_string(f));
    Ok(())
}

/// Format a finite, non-integral f64 exactly as ECMAScript `Number::toString`.
fn es6_number_to_string(f: f64) -> String {
    let neg = f < 0.0;
    let f = f.abs();
    // `{:e}` yields the shortest round-trip digits as d.ddde±x.
    let text = format!("{:e}", f);
    let (mant, exp_str) = text.split_once('e').unwrap_or((&text, "0"));
    let mut exp: i64 = exp_str.parse().unwrap_or(0);
    let (int_part, frac_part) = mant.split_once('.').unwrap_or((mant, ""));
    let mut digits: String = format!("{}{}", int_part, frac_part)
        .trim_start_matches('0')
        .to_string();
    exp -= frac_part.len() as i64;
    let trimmed = digits.trim_end_matches('0').to_string();
    exp += (digits.len() - trimmed.len()) as i64;
    digits = trimmed;
    let k = digits.len() as i64;
    let n = exp + k;

    let body = if n > 0 && n <= 21 {
        let (a, b) = digits.split_at(n as usize);
        format!("{}.{}", a, b)
    } else if n > -6 && n <= 0 {
        format!("0.{}{}", "0".repeat((-n) as usize), digits)
    } else {
        let e = n - 1;
        let sign = if e < 0 { '-' } else { '+' };
        let mant = if k == 1 {
            digits.clone()
        } else {
            format!("{}.{}", &digits[..1], &digits[1..])
        };
        format!("{}e{}{}", mant, sign, e.abs())
    };
    if neg {
        format!("-{}", body)
    } else {
        body
    }
}

// ---------------------------------------------------------------------------
// Strict parser
// ---------------------------------------------------------------------------

/// Parse JSON text strictly for canonicalization.
///
/// Rejects duplicate object keys, `NaN`/`Infinity`, numbers outside the
/// 2^53 - 1 safe range, lone surrogates, invalid UTF-8 and unescaped control
/// characters (`serde_json` already enforces the last three).
pub fn parse_schema_json(text: &str) -> Result<Value, Error> {
    let strict: StrictValue =
        serde_json::from_str(text).map_err(|e| canon_err(format!("invalid JSON: {}", e)))?;
    validate_numbers(&strict.0)?;
    Ok(strict.0)
}

fn validate_numbers(value: &Value) -> Result<(), Error> {
    match value {
        Value::Number(n) => {
            let mut scratch = String::new();
            write_number(&mut scratch, n)
        }
        Value::Array(items) => items.iter().try_for_each(validate_numbers),
        Value::Object(map) => map.values().try_for_each(validate_numbers),
        _ => Ok(()),
    }
}

/// `serde_json::Value` wrapper whose `Deserialize` impl rejects duplicate keys.
struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = StrictValue;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(v)))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::from(v)))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::from(v)))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
        Number::from_f64(v)
            .map(|n| StrictValue(Value::Number(n)))
            .ok_or_else(|| E::custom("non-finite number"))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(v.to_string())))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(v)))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut items = Vec::new();
        while let Some(StrictValue(v)) = seq.next_element()? {
            items.push(v);
        }
        Ok(StrictValue(Value::Array(items)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            let StrictValue(v) = map.next_value()?;
            if object.insert(key.clone(), v).is_some() {
                return Err(de::Error::custom(format!(
                    "duplicate object key \"{}\"",
                    key
                )));
            }
        }
        Ok(StrictValue(Value::Object(object)))
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
        let canonical = canonicalize_schema(&schema).unwrap();
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
        let canonical = canonicalize_schema(&schema).unwrap();
        assert_eq!(canonical, r#"{"a":{"c":3,"d":4},"z":{"a":1,"b":2}}"#);
    }

    #[test]
    fn test_arrays_preserve_order() {
        let schema = json!({
            "items": [3, 1, 2],
            "name": "test"
        });
        let canonical = canonicalize_schema(&schema).unwrap();
        assert_eq!(canonical, r#"{"items":[3,1,2],"name":"test"}"#);
    }

    #[test]
    fn test_deterministic_hash() {
        let schema = json!({
            "name": "calculate_sum",
            "description": "Calculates the sum",
            "parameters": { "b": "integer", "a": "integer" }
        });
        let hash1 = canonicalize_and_hash(&schema).unwrap();
        let hash2 = canonicalize_and_hash(&schema).unwrap();
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn test_key_order_independence() {
        let schema_a = json!({"z": 1, "a": 2, "m": 3});
        let schema_b = json!({"a": 2, "m": 3, "z": 1});
        assert_eq!(
            canonicalize_schema(&schema_a).unwrap(),
            canonicalize_schema(&schema_b).unwrap()
        );
    }

    #[test]
    fn test_hash_canonical_output() {
        let canonical = r#"{"name":"test"}"#;
        let hash = hash_canonical(canonical);
        assert_eq!(hash.len(), 32);
        assert_eq!(hash, hash_canonical(canonical));
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
        let canonical = canonicalize_schema(&schema).unwrap();
        assert_eq!(
            canonical,
            r#"{"level1":{"level2":{"a":"first","z":"last"}}}"#
        );
    }

    #[test]
    fn test_numbers_es6_format() {
        let v =
            parse_schema_json(r#"[1e-7,0.000001,123.456,1e3,-0.0,0.1,1.5e-10,5e-324,1.0,-2.5]"#)
                .unwrap();
        assert_eq!(
            canonicalize_schema(&v).unwrap(),
            "[1e-7,0.000001,123.456,1000,0,0.1,1.5e-10,5e-324,1,-2.5]"
        );
    }

    #[test]
    fn test_numbers_out_of_range_rejected() {
        for text in [
            "9007199254740992",
            "-9007199254740992",
            "1e21",
            "1e16",
            "18446744073709551616",
        ] {
            assert!(
                parse_schema_json(text).is_err(),
                "{} must be rejected",
                text
            );
        }
        assert!(parse_schema_json("9007199254740991").is_ok());
    }

    #[test]
    fn test_string_escaping_rules() {
        let v = parse_schema_json(
            "{\"s\":\"<>&\u{2028}\u{2029}\\u0000\\u001f\\b\\f\\n\\r\\t\\\"\\\\\\u007f\"}",
        )
        .unwrap();
        assert_eq!(
            canonicalize_schema(&v).unwrap(),
            "{\"s\":\"<>&\u{2028}\u{2029}\\u0000\\u001f\\b\\f\\n\\r\\t\\\"\\\\\u{7f}\"}"
        );
    }

    #[test]
    fn test_key_order_is_code_point() {
        let v = parse_schema_json(r#"{"😀":1,"￿":2,"z":3}"#).unwrap();
        assert_eq!(
            canonicalize_schema(&v).unwrap(),
            "{\"z\":3,\"\u{ffff}\":2,\"\u{1f600}\":1}"
        );
    }

    #[test]
    fn test_proto_key_preserved() {
        let v = parse_schema_json(r#"{"__proto__":{"polluted":1},"name":"x"}"#).unwrap();
        assert_eq!(
            canonicalize_schema(&v).unwrap(),
            r#"{"__proto__":{"polluted":1},"name":"x"}"#
        );
    }

    #[test]
    fn test_duplicate_keys_rejected() {
        assert!(parse_schema_json(r#"{"a":1,"a":2}"#).is_err());
        assert!(parse_schema_json(r#"{"o":{"a":1,"b":2,"a":3}}"#).is_err());
        assert!(parse_schema_json(r#"{"a":1,"b":2}"#).is_ok());
    }

    #[test]
    fn test_nan_and_lone_surrogate_rejected() {
        assert!(parse_schema_json(r#"{"a":NaN}"#).is_err());
        assert!(parse_schema_json(r#"{"a":Infinity}"#).is_err());
        assert!(parse_schema_json(r#"{"a":"\ud800"}"#).is_err());
        assert!(parse_schema_json(r#"{"a":"\udc00"}"#).is_err());
    }
}
