# Cross-language interop fixtures

Every fixture in this directory is asserted by all four SDK test suites
(Python, JavaScript, Go, Rust). They are the normative proof that the SDKs
agree on the bytes that get signed. If a wire format changes, regenerate the
affected fixtures and make sure all four suites still pass.

## `canonicalization/*.json`

One vector per file. Each file has:

| Field                | Meaning                                                                 |
|----------------------|-------------------------------------------------------------------------|
| `name`               | Vector id (matches the file name)                                       |
| `description`        | What the vector exercises                                               |
| `input`              | Raw JSON text to parse with the SDK's strict parser                     |
| `reject`             | `true` if the input MUST fail to parse or canonicalize                  |
| `expected_canonical` | The exact `schemapin-v1` canonical string (absent when `reject`)        |
| `expected_sha256`    | Lowercase hex SHA-256 of the UTF-8 canonical bytes (absent when `reject`)|

The vectors cover HTML-sensitive characters (`<>&`), U+2028/U+2029, C0
control escapes, non-ASCII literals, code-point key ordering (astral
characters), number formatting (ES6 `Number::toString`, integral floats, `-0`),
the 2^53-1 magnitude limit, `__proto__` preservation, and the rejection cases
(duplicate keys, `NaN`/`Infinity`, lone surrogates, oversized numbers, parse
errors). The rules themselves are in TECHNICAL_SPECIFICATION.md section 4.

Consumers:

- `python/tests/test_cross_language.py`
- `javascript/tests/cross-language.test.js`
- `go/pkg/core/cross_language_test.go`
- `rust/tests/cross_language_canonicalization.rs`

## `signatures/schema-signature.json`

A fixed ECDSA P-256 schema signature: the schema, its canonical form and
SHA-256, the public key and fingerprint, the signature, a copy of the signature
with a trailing DER byte (must be rejected) and a tampered schema (must be
rejected). Proves the signing construction `ECDSA(SHA-256(digest))` is shared.

## `skill/`

`fixture-skill/` is a skill directory with a v1.4 signed signature document
(skill canonicalization v2); `legacy-v13-skill/` carries a pre-1.4 root-hash
only signature. `expected.json` lists the expected `skill_hash` and
`file_manifest` for both, the discovery document to verify against, and the
signed fields whose tampering must fail. Both directories must verify in every
SDK; the v1.4 one must fail for every tampered field and for any content
change.

## `signed_bundle.json`

A v1.4 signed trust bundle signed by the test-only authority
`schemapin-test-fixture-authority`. Each SDK's test seeds that authority from
`keys/test-only-bundle-authority.pub.pem` and asserts the bundle verifies,
that it is refused without seeding, and that a different seeded key is
reported as `KEY_PIN_MISMATCH`.

## `keys/`

Test-only key material. Nothing in this directory is a production identity:
the bundle authority kid is deliberately named `schemapin-test-fixture-authority`
so it cannot be mistaken for a real authority, and verifiers must never seed a
persistent authority store with it outside of a test run.

| File | Purpose |
|------|---------|
| `test-only-signing-key.pem` / `.pub.pem` | Signs the schema vector and the skill fixtures |
| `test-only-bundle-authority.pem` / `.pub.pem` | Signs `signed_bundle.json` |
| `reject-p384-public.pem`, `reject-rsa2048-public.pem` | Keys every SDK must refuse (spec section 10) |
