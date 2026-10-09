#![no_main]
use libfuzzer_sys::fuzz_target;
use schemapin::crypto::{calculate_key_id, verify_signature};

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = calculate_key_id(text);
        let _ = verify_signature(text, b"x", "AAAA");
    }
});
