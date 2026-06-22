# Cross-language interop fixtures

`signed_bundle.json` is a v1.4 signed trust bundle produced by the Rust SDK
(`sign_trust_bundle`), signed with `go/schemapin_private.pem` under the bundle
authority kid `schemapin-bundle-authority-2026`. The authority public key is
embedded in `bundle_authority.public_key_pem`, so the bundle is self-verifying.

Each SDK has a test that loads this file and asserts `verify_trust_bundle`
succeeds — proving the four SDKs agree on the bundle canonicalization and
signing input. Regenerate by re-signing the same input if the wire format
changes; all four SDK tests must still pass.
