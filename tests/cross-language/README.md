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

## `signed_bundle.json`

A v1.4 signed trust bundle. See the `keys/` section below for the test
authority that signed it.

## `keys/`

Test-only key material. Nothing in this directory is a production identity:
the bundle authority kid is deliberately named `schemapin-test-fixture-authority`
so it cannot be mistaken for a real authority, and verifiers must never seed a
persistent authority store with it outside of a test run.
