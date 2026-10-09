# Fuzz targets

libFuzzer targets for the parsers that face untrusted input. They are not part
of the regular test run; install `cargo-fuzz` (nightly) and run, for example:

```bash
cargo +nightly fuzz run canonicalize -- -max_total_time=300
```

Targets: `canonicalize` (strict JSON parser + idempotence), `txt_record`
(DNS TXT parser), `skill_signature` (`.schemapin.sig` documents),
`bundle` (trust bundle parse/verify/merge) and `pem_loader` (public keys and
signatures). The same properties run under `proptest` in
`tests/property.rs` on stable as part of `cargo test`.
