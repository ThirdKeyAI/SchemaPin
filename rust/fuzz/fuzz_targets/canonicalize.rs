#![no_main]
use libfuzzer_sys::fuzz_target;
use schemapin::canonicalize::{canonicalize_schema, parse_schema_json};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    if let Ok(value) = parse_schema_json(text) {
        let c1 = canonicalize_schema(&value).expect("parsed value must canonicalize");
        let again = parse_schema_json(&c1).expect("canonical output must re-parse");
        assert_eq!(canonicalize_schema(&again).unwrap(), c1, "not idempotent");
    }
});
