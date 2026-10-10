#![no_main]
use libfuzzer_sys::fuzz_target;
use schemapin::dns::parse_txt_record;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(rec) = parse_txt_record(text) {
            assert!(rec.fingerprint.starts_with("sha256:"));
        }
    }
});
