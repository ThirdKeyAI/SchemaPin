#![no_main]
use libfuzzer_sys::fuzz_target;
use schemapin::skill::{signing_input, SkillSignature};

fuzz_target!(|data: &[u8]| {
    if let Ok(sig) = serde_json::from_slice::<SkillSignature>(data) {
        let _ = signing_input(&sig);
    }
});
