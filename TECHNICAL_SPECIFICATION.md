# SchemaPin: A Technical Specification

Version 1.4 (alpha.3)

Status: Draft

> **What's new in v1.4 alpha.3 (2026-05-16, additive, wire-compatible
> with v1.3 / v1.4 alpha.1 / v1.4 alpha.2):**
> §19 introduces an optional `canonicalization` field on `.schemapin.sig`
> for forward-compatibility with future canonicalization algorithms;
> unknown values are a hard failure (`CANONICALIZATION_UNSUPPORTED`).
> §20 introduces `A2aVerificationContext` and `verify_schema_for_a2a` for
> A2A-aware verification, interoperating with AgentPin v0.3's
> `AllowedDomains` typed wrapper. The scope check uses the empty-list
> means *unrestricted* convention (AgentPin spec §4.11) and enforces a
> delegation-depth cap matching AgentPin's `max_delegation_depth`.

### **1. Introduction**

This document provides the technical specification for SchemaPin, a protocol designed to ensure the integrity and authenticity of tool schemas used by AI agents. By enabling developers to cryptographically sign their tool schemas, SchemaPin allows agent clients to verify that a schema has not been altered since its publication. This provides a robust defense against supply-chain attacks like the MCP Rug Pull, where a benign schema is maliciously replaced after being approved.

The key design goals of this protocol are:

- **Security:** To provide strong, verifiable guarantees of schema integrity.
- **Interoperability:** To define a common standard that can be adopted by any agent framework or tool provider.
- **Simplicity:** To provide a straightforward implementation path for both developers and client applications.

### **2. Core Concepts**

- **Tool Schema:** A JSON object that defines a tool's capabilities, parameters, and descriptions, as consumed by an LLM agent.
- **Digital Signature:** A cryptographic value that provides a guarantee of data integrity and authenticity. It is created using a private key and can be verified by anyone with the corresponding public key.
- **Public Key Infrastructure (PKI):** The framework of policies and procedures for managing cryptographic keys. In SchemaPin, this primarily concerns how public keys are published and discovered.
- **Schema Pinning:** The act of a client application associating a tool with a specific public key upon first use. The client will only accept schemas for that tool signed by the private key corresponding to the pinned public key.

### **3. Cryptographic Primitives**

To ensure universal compatibility and strong security, implementations of SchemaPin **MUST** adhere to the following standards:

- **Hashing Algorithm:** **SHA-256**.
- **Signature Algorithm:** **ECDSA with the P-256 curve** (also known as `secp256r1`).
- **Key Encoding:** Public keys **MUST** be encoded in the PEM (Privacy-Enhanced Mail) format.

### **4. Schema Canonicalization**

To ensure that a signature is valid across different platforms and environments, the tool schema's JSON object **MUST** be converted to a canonical string format before hashing and signing. The algorithm is identified as `schemapin-v1` (see Section 19) and is defined normatively here; the shared conformance corpus in `tests/cross-language/canonicalization/` is the reference for the exact bytes, and every implementation **MUST** pass it.

1. **Encoding:** The canonical string **MUST** be encoded as UTF-8. Input that is not valid UTF-8 **MUST** be rejected.
2. **Whitespace:** All insignificant whitespace between JSON elements **MUST** be removed.
3. **Key Sorting:** The names in every JSON object **MUST** be sorted by Unicode code point (equivalently, by the UTF-8 byte sequence of the name). This is *not* UTF-16 code-unit order: `"z"` (U+007A) sorts before U+FFFF, which sorts before U+1F600. Sorting is applied recursively to nested objects; array element order is preserved.
4. **Duplicate Keys:** An object containing the same name more than once has no canonical form and **MUST** be rejected.
5. **Strings:** Strings are emitted with the minimal escaping set: `"` as `\"`, `\` as `\\`, U+0008, U+000C, U+000A, U+000D and U+0009 as `\b`, `\f`, `\n`, `\r`, `\t`, and every other control character below U+0020 as lowercase `\u00xx`. Every other code point — including `/`, `<`, `>`, `&`, U+007F, U+2028 and U+2029 and all non-ASCII — **MUST** be emitted literally. Lone surrogates have no canonical form and **MUST** be rejected.
6. **Numbers:** Numbers are interpreted as IEEE 754 binary64 values. Any number whose absolute value exceeds 2^53 − 1 (9007199254740991) **MUST** be rejected, so that no two distinct inputs can collide after rounding; `NaN` and infinities are not JSON and **MUST** be rejected. Integral values are emitted as plain decimal integers without a sign for zero (`1.0` → `1`, `1e3` → `1000`, `-0` → `0`). Non-integral values are emitted with the ECMAScript `Number::toString` algorithm (RFC 8785 Section 3.2.2.3): shortest round-trip digits, fixed notation for exponents between −7 and 21, otherwise `d.ddde±N` (`0.1`, `0.000001`, `1e-7`, `123.456`).
7. **Literals:** `true`, `false` and `null` are emitted as such.
8. **Special-looking keys:** Names such as `__proto__`, `constructor` or `prototype` are ordinary keys and **MUST** be preserved and signed; implementations in languages where such names have prototype semantics **MUST** serialize without materializing intermediate objects.

Example:

The following non-canonical JSON:

```
{
  "description": "Calculates the sum",
  "name": "calculate_sum",
  "parameters": { "b": "integer", "a": "integer"}
}
```

Becomes the following canonical string before signing:

`{"description":"Calculates the sum","name":"calculate_sum","parameters":{"a":"integer","b":"integer"}}`

#### **4.1. Signature Input**

The schema signature is an ECDSA P-256 signature with SHA-256 whose message is the 32-byte SHA-256 digest of the canonical UTF-8 bytes (that is, ECDSA is applied to SHA-256(SHA-256(canonical))). All implementations **MUST** use exactly this construction; `tests/cross-language/signatures/schema-signature.json` is the reference vector.

### **4b. Skill Directory Canonicalization (v1.4)**

Skill signing (Section 16 and `docs/skill-signing.md`) hashes a directory tree rather than a JSON document. The algorithm, identified by `schemapin_version: "1.4"` in the signature document, is:

1. Walk the directory. Directories themselves are not entries; empty directories are not covered. The top-level `.schemapin.sig` is excluded.
2. Any symbolic link (to a file or a directory) or non-regular file **MUST** abort canonicalization: unsigned content must never be reachable from a signed skill. Paths that are not valid UTF-8 **MUST** be rejected. Implementations **MUST** cap the number of entries and the total size (the reference SDKs use 10 000 entries and 256 MiB).
3. Each entry's path is its forward-slash-separated path relative to the skill root, encoded as UTF-8; entries are sorted by code point.
4. Entry digest: `SHA-256(0x66 ‖ be64(len(path)) ‖ path ‖ be64(len(content)) ‖ content)` where `be64` is the 64-bit big-endian length. The `file_manifest` maps each path to `"sha256:" + hex(entry digest)`.
5. Root hash: `SHA-256` over the concatenation, in sorted order, of `be64(len(path)) ‖ path ‖ entry digest` for every entry. `skill_hash` is `"sha256:" + hex(root hash)`.

The signature document is then built with every field present and `signature` set to `""`, canonicalized with `schemapin-v1` (Section 4), and signed as ECDSA P-256 with SHA-256 over the canonical bytes. Verifiers **MUST** recompute the root hash, require `skill_hash` to equal it, rebuild the signing input from the parsed known fields (unknown fields are ignored and therefore unprotected) and verify the signature over those bytes. `tests/cross-language/skill/` holds the reference fixture.

Documents with `schemapin_version` below `"1.4"` use the legacy algorithm (`SHA-256(path ‖ content)` per file, root hash over the concatenated hex digests, symlinks skipped, signature over the 32-byte root hash only). Verifiers **MAY** accept them for compatibility but **MUST** surface that none of their metadata fields is signed (the reference SDKs emit a `legacy_signature_format` warning), and **MUST NOT** anchor lineage (Section 18) on them. New signatures **MUST NOT** use the legacy format.

### **5. Signature and Key Formats**

- **Signature:** The generated signature **MUST** be a **detached signature**, encoded in **Base64**. It should be distributed as a separate file or field alongside the schema itself (e.g., in an `x-schema-signature` HTTP header or a `signature` field in a manifest file).

- **Public Key:** The developer's public key **MUST** be published in PEM format.

### **6. Public Key Discovery**

A client application needs a reliable way to find the correct public key for a given tool. This specification recommends a discovery mechanism based on the IETF's RFC 8615 for `.well-known` URIs.

A tool provider SHOULD host a JSON file at:

https://[tool_domain]/.well-known/schemapin.json

The contents of this file should be a JSON object specifying the public key:

```json
{
  "schema_version": "1.2",
  "developer_name": "Example Corp Tools",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...etc...\n-----END PUBLIC KEY-----",
  "revoked_keys": [
    "sha256:abc123def456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
    "sha256:def456789abc123def456789abc123def456789abc123def456789abc123def4"
  ],
  "contact": "security@example.com",
  "revocation_endpoint": "https://example.com/.well-known/schemapin-revocations.json"
}
```

The `contact` and `revocation_endpoint` fields are OPTIONAL. The `revocation_endpoint` field, when present, specifies a URL where a standalone revocation document (see Section 8.5) can be fetched.

### **7. The SchemaPin Workflow**

#### **7.1. For Tool Developers (Signing)**

1. **Generate Key Pair:** Generate a new ECDSA P-256 key pair. Keep the private key secure.
2. **Publish Public Key:** Host the public key at the `.well-known` URI.
3. **Sign Schema:** For each tool release:

    a. Generate the tool's JSON schema.

    b. Canonicalize the schema according to Section 4.

    c. Hash the canonical string using SHA-256.

    d. Sign the resulting hash with the private key.

    e. Encode the signature in Base64.

4. **Publish Tool:** Distribute the tool's schema along with its detached Base64 signature.

#### **7.2. For Agent Clients (Verification)**

1. **Fetch Schema & Signature:** Retrieve the tool schema and its associated signature.
2. **Discover Public Key:**
    a. Check for a locally "pinned" public key for this tool/developer.
    b. If no key is pinned, construct the .well-known URI based on the tool's domain and fetch the public key.

    c. Pin the Key: After the signature in step 3 has verified, store the public key locally and associate it with the tool's identifier *and* the domain it was fetched for. This is the "pinning" step; a failed verification **MUST NOT** leave a pin behind. The user **SHOULD** be prompted for confirmation before trusting a new key — automatic first-use pinning is an explicit opt-in, not the default — and a fingerprint obtained out of band (for example from a DNS TXT record, Section 17) **MAY** be seeded in advance.

3. Verify:
    a. Canonicalize the fetched schema using the exact rules in Section 4.
    b. Hash the canonical string with SHA-256.
    c. Using the pinned public key, verify the signature against the hash.

4. **Execute or Reject:**

    - If the signature is **valid**, the client can proceed to use the tool schema.
    - If the signature is **invalid**, the client **MUST** refuse to use the tool and should alert the user of a potential security risk.

### **8. Key Revocation**

SchemaPin v1.1 introduces a key revocation mechanism to handle compromised or deprecated keys.

#### **8.1. Revocation List Format**

The `.well-known/schemapin.json` file MAY include an optional `revoked_keys` array containing SHA-256 fingerprints of revoked public keys:

```json
{
  "schema_version": "1.2",
  "developer_name": "Example Corp Tools",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...current_key...\n-----END PUBLIC KEY-----",
  "revoked_keys": [
    "sha256:abc123def456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
  ]
}
```

#### **8.2. Key Fingerprint Calculation**

Key fingerprints MUST be calculated as follows:
1. Export the public key in DER format using SubjectPublicKeyInfo encoding
2. Calculate the SHA-256 hash of the DER-encoded bytes
3. Format as `sha256:` followed by the lowercase hexadecimal representation

#### **8.3. Revocation Checking**

Clients MUST check if a public key is revoked before using it for signature verification:
1. Fetch the current `.well-known/schemapin.json` file
2. Calculate the fingerprint of the public key to be used
3. Check if the fingerprint appears in the `revoked_keys` array
4. If the key is revoked, immediately reject the schema with an appropriate error message

#### **8.4. Backward Compatibility**

- Schema version 1.0 endpoints without `revoked_keys` are still valid
- Clients MUST gracefully handle missing `revoked_keys` fields
- Empty `revoked_keys` arrays indicate no keys are currently revoked

#### **8.5. Standalone Revocation Document**

SchemaPin v1.2 introduces a standalone revocation document that can be hosted separately from the discovery endpoint. When a `revocation_endpoint` URL is present in the `.well-known` response, clients SHOULD fetch and check this document in addition to the simple `revoked_keys` list.

The revocation document format:

```json
{
  "schemapin_version": "1.2",
  "domain": "example.com",
  "updated_at": "2026-02-11T00:00:00Z",
  "revoked_keys": [
    {
      "fingerprint": "sha256:abc123def456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
      "revoked_at": "2026-02-10T00:00:00Z",
      "reason": "key_compromise"
    }
  ]
}
```

#### **8.6. Revocation Reasons**

Each revoked key entry in a standalone revocation document MUST include a `reason` field with one of the following values:

- `key_compromise` — The private key has been compromised or is suspected to be compromised.
- `superseded` — The key has been replaced by a newer key.
- `cessation_of_operation` — The key is no longer in use because the associated tool or service has been discontinued.
- `privilege_withdrawn` — The key holder's authorization to sign schemas has been revoked.

#### **8.7. Combined Revocation Checking**

Clients MUST check both revocation sources when available:
1. Check the simple `revoked_keys` array in the `.well-known` response
2. If a `revocation_endpoint` is present, fetch the standalone revocation document and check its `revoked_keys` list
3. If the key fingerprint appears in either source, reject the schema

### **9. Security Considerations**

- **Key Revocation:** Keys MUST be immediately revoked upon suspected compromise. Clients MUST check revocation status before each verification.
- **Key Compromise:** A developer whose private key is compromised must generate a new key pair and work with client applications to transition trust to the new key.
- **Transport Security:** All communications for public key discovery MUST use HTTPS to prevent man-in-the-middle attacks during the initial key fetch. Implementations MUST refuse `http://` (including domain strings that carry a scheme), MUST NOT follow redirects, MUST apply connect and read timeouts, MUST cap the response body (the reference SDKs use 64 KiB), and MUST validate the domain against the RFC 1123 hostname grammar (ASCII, at least two labels, no scheme, path, port, userinfo or IP literal) before building a URL, a pin key or a local file path from it.
- **Revocation Availability:** A declared `revocation_endpoint` (or `.well-known` document) that cannot be fetched is a verification failure (`DISCOVERY_FETCH_FAILED`), not "not revoked". Implementations MAY offer an explicit opt-out for air-gapped use, but the default MUST fail closed.
- **Key Pinning:** Once a public key is pinned for a tool, clients MUST NOT automatically accept a different key without explicit user consent, even if served from the same `.well-known` endpoint.
- **Signature Validation:** Clients MUST validate signatures before executing any tool functionality. Invalid signatures MUST result in immediate rejection of the tool.
- **Canonical Form Consistency:** All implementations MUST use identical canonicalization rules to ensure signature compatibility across different platforms and libraries.
- **Private Key Storage:** Developers MUST store private keys securely using appropriate key management practices, including encryption at rest and restricted access controls.
- **Clock Skew:** While this specification does not include timestamp validation, implementations should be aware that future versions may include time-based validity checks.

### **10. Error Handling**

Implementations MUST handle the following error conditions gracefully:

- **Network Failures:** When `.well-known` endpoints are unreachable, clients should fall back to cached keys if available, or prompt users for manual key verification.
- **Invalid Signatures:** Clients MUST reject schemas with invalid signatures and provide clear error messages to users indicating potential security risks.
- **Malformed Keys:** Public keys that cannot be parsed or are not valid ECDSA P-256 keys MUST be rejected.
- **Missing Signatures:** Schemas without associated signatures MUST be treated as unsigned and handled according to the client's security policy.
- **Canonicalization Errors:** JSON schemas that cannot be canonicalized (e.g., due to circular references) MUST be rejected.

### **11. Implementation Guidelines**

- **Library Dependencies:** Implementations SHOULD use well-established cryptographic libraries (e.g., OpenSSL, cryptography.io) rather than custom implementations.
- **Testing:** All implementations MUST include comprehensive test suites covering signature generation, verification, and error conditions.
- **Backwards Compatibility:** Future versions of this specification will maintain backwards compatibility with version 1.0 signatures.
- **Performance:** Signature verification should be optimized for client-side performance, as it may be performed frequently during tool discovery.

### **12. Version Compatibility**

- **Schema Version:** This specification is version 1.4. The `schema_version` field in `.well-known` files indicates compatibility.
- **Backward Compatibility:** Version 1.4 clients MUST support version 1.0–1.3 endpoints for backward compatibility. The `revocation_endpoint`, `contact`, standalone revocation document, `expires_at`, and `_schemapin.{domain}` TXT record are all optional and additive.
- **Future Versions:** Clients SHOULD gracefully handle unknown schema versions by falling back to the highest supported version.
- **Deprecation Policy:** Any breaking changes will be introduced in new major versions with appropriate migration guidance.

### **13. Trust Bundles**

SchemaPin v1.2 introduces trust bundles for offline and air-gapped verification scenarios.

A trust bundle is a pre-shared collection of discovery documents and revocation documents. This allows verification in environments where the standard `.well-known` HTTP discovery is unavailable (air-gapped networks, CI pipelines, enterprise-internal tools, etc.).

#### **13.1. Trust Bundle Format**

```json
{
  "schemapin_bundle_version": "1.2",
  "created_at": "2026-02-11T00:00:00Z",
  "documents": [
    {
      "domain": "example.com",
      "schema_version": "1.2",
      "developer_name": "Example Corp",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
      "revoked_keys": []
    }
  ],
  "revocations": [
    {
      "schemapin_version": "1.2",
      "domain": "example.com",
      "updated_at": "2026-02-11T00:00:00Z",
      "revoked_keys": []
    }
  ]
}
```

#### **13.2. Use Cases**

- **Air-gapped environments:** Systems without internet access can verify schemas using a locally distributed trust bundle.
- **CI/CD pipelines:** Build systems can include a trust bundle to verify tool schemas during automated builds.
- **Enterprise deployment:** Organizations can distribute approved trust bundles containing vetted developer keys.
- **Testing:** Developers can create trust bundles for deterministic testing of verification workflows.

### **14. Discovery Resolver**

SchemaPin v1.2 introduces a resolver abstraction that decouples verification logic from the discovery mechanism.

#### **14.1. SchemaResolver Trait**

Implementations SHOULD provide a `SchemaResolver` interface with two methods:

- `resolve_discovery(domain)` — Returns the well-known response for a domain.
- `resolve_revocation(domain, discovery)` — Returns the revocation document for a domain, if available. Defaults to returning nothing.

#### **14.2. Standard Implementations**

Four resolver implementations are defined:

1. **WellKnownResolver** — Fetches documents from the standard `.well-known` HTTPS endpoint. Requires HTTP capabilities (feature-gated in Rust as `fetch`).
2. **LocalFileResolver** — Reads `{domain}.json` and `{domain}.revocations.json` from a local filesystem directory.
3. **TrustBundleResolver** — Resolves documents from an in-memory trust bundle (see Section 13).
4. **ChainResolver** — Tries a sequence of resolvers in order until one succeeds (first-wins fallthrough).

#### **14.3. Feature Gating**

In the Rust implementation, HTTP-based resolvers and async variants are gated behind the `fetch` feature flag. All other resolvers (LocalFile, TrustBundle, Chain) are always available.

### **15. Offline Verification**

SchemaPin v1.2 defines `verify_schema_offline()` as the core verification primitive. All other verification functions delegate to it.

#### **15.1. Seven-Step Verification Flow**

1. **Validate discovery document** — Check that the well-known response is structurally valid (non-empty PEM key, valid schema version).
2. **Extract public key and compute fingerprint** — Parse the PEM public key and calculate its SHA-256 fingerprint.
3. **Check revocation** — Check both the simple `revoked_keys` list and any standalone revocation document.
4. **TOFU key pinning check** — Compare the key fingerprint with the pin store for `tool_id@domain` without writing. On match, continue. On change, reject with `KEY_PIN_MISMATCH`. On first use, remember that a pin must be written later.
5. **Canonicalize schema** — Apply the canonicalization rules from Section 4 and compute the SHA-256 hash.
6. **Verify ECDSA signature** — Verify the Base64-encoded signature against the schema hash using the public key.
7. **Pin and return** — Only after step 6 succeeds, pin the fingerprint on first use, then return a structured `VerificationResult` with the domain, developer name, key pinning status, and any errors or warnings. A failed verification never writes a pin. The `domain` argument MUST be validated (Section 9) and is the only source of the pin key and of the reported domain.

### **16. Signature Expiration (v1.4)**

SchemaPin v1.4 introduces an OPTIONAL `expires_at` field on signature documents (both schema signatures and `.schemapin.sig` for skills).

#### **16.1. Format**

The `expires_at` field is an ISO 8601 / RFC 3339 timestamp in UTC:

```json
{
  "schemapin_version": "1.4",
  "skill_name": "example-skill",
  "skill_hash": "sha256:...",
  "signature": "MEUCIQ...",
  "signed_at": "2026-04-30T12:00:00Z",
  "expires_at": "2026-10-30T12:00:00Z",
  "domain": "thirdkey.ai",
  "signer_kid": "thirdkey-2026-04",
  "file_manifest": { /* ... */ }
}
```

A signature document with `expires_at` MUST set `schemapin_version` to `"1.4"` or higher, which also selects the signed-document format of Section 4b so that `expires_at` is covered by the signature. New signatures use `"1.4"` whether or not they expire.

#### **16.2. Verifier Semantics**

Expiration is **fail-closed**. When the current time is more than the clock-skew allowance (300 seconds) past `expires_at`, verifiers MUST fail with `SIGNATURE_EXPIRED` and MUST set `expired: true` and mirror `expires_at` on the result. `expires_at` MUST be a strict RFC 3339 timestamp (`T` separator, mandatory `Z` or numeric offset); a value that does not parse MUST also fail with `SIGNATURE_EXPIRED` — a malformed expiry is indistinguishable from a stripped one.

Verifiers MAY offer an explicit per-call opt-in (`allow_expired`) that restores the original "degraded" behavior: `valid` stays `true`, `expired` is set, and a `signature_expired` (or `signature_expires_at_unparseable`) warning is appended for confidence scoring. That mode is a policy decision by the host and MUST NOT be the default.

**Risk statement.** The degraded mode was the default in v1.4.0-alpha.1 through alpha.4. Because every library exit reported `valid: true` for expired signatures and no shipped consumer checked `expired`, expiry provided no security property; combined with the then-unsigned `expires_at` field (Section 4b) it could be stripped or altered freely. From this revision `expires_at` is covered by the signature and expiry fails closed.

#### **16.3. Backward Compatibility**

- v1.3 verifiers ignore the `expires_at` field entirely; signatures continue to verify.
- v1.4 signatures without `expires_at` behave identically to v1.3 signatures.

### **17. DNS TXT Cross-Verification (v1.4)**

The cross-check applies to both skill and schema verification (`verify_skill_offline_with_dns` and `verify_schema_offline_with_dns`), runs before any pin is written, and a mismatch is a hard `DOMAIN_MISMATCH` failure.

SchemaPin v1.4 adds an OPTIONAL second-channel verification mechanism via DNS TXT records. The DNS credential chain is independent of the HTTPS hosting credential chain, so an attacker compromising one does not automatically gain control of the other.

#### **17.1. TXT Record Format**

A tool provider MAY publish a TXT record at `_schemapin.{domain}` containing the public-key fingerprint advertised in `.well-known/schemapin.json`:

```
_schemapin.example.com. IN TXT "v=schemapin1; kid=acme-2026-04; fp=sha256:a1b2c3d4..."
```

Fields:

| Field | Required | Description |
|-------|----------|-------------|
| `v` | yes | Version tag, currently `schemapin1` |
| `fp` | yes | Key fingerprint as `sha256:<hex>` (lowercase hex) |
| `kid` | no | Optional key id, useful for multi-key endpoints (v1.5+) |

Whitespace around `;` and `=` SHOULD be tolerated by parsers. Field order is not significant. Unknown fields MUST be ignored for forward compatibility.

If multiple TXT records exist at the same name, parsers MUST select the first record containing `v=schemapin1`. Multiple TXT chunks within a single record MUST be concatenated in emit order per RFC 1464.

#### **17.2. Verifier Semantics**

| State | Effect |
|-------|--------|
| **Absent** | No effect — DNS TXT cross-verification is optional |
| **Present and matching** | Verification succeeds; absence of mismatch is the trust signal |
| **Present and mismatching** | Hard failure with `DOMAIN_MISMATCH` error code |
| **Present and malformed** | Hard failure with `DISCOVERY_INVALID` error code |

The mismatch case is fail-closed because a publishing party that *intentionally* publishes a TXT record has signaled that DNS is part of their trust chain — a divergence between DNS and `.well-known` indicates compromise of one channel.

#### **17.3. Backward Compatibility**

- Verifiers MAY skip DNS TXT lookups entirely (the feature is additive).
- Tool providers MAY publish or omit the TXT record without affecting v1.3 verifiers.
- Implementations SHOULD gate DNS resolution behind a feature flag (e.g., the `dns` Cargo feature in Rust) to keep the core library DNS-free.

#### **17.4. Lookup Name Construction**

Implementations MUST strip a single trailing dot from the input domain before constructing the lookup name:

```
input "example.com"  → "_schemapin.example.com"
input "example.com." → "_schemapin.example.com"
```

### **18. Schema Version Binding (v1.4)**

SchemaPin v1.4 adds two OPTIONAL fields to signature documents that, together, defend against rug-pull attacks where an attacker substitutes a tampered schema or skill out-of-band under the same name as a previously trusted version.

#### **18.1. Format**

Two new optional fields on `.schemapin.sig` (and on schema signatures by extension):

```json
{
  "schemapin_version": "1.4",
  "skill_name": "example-skill",
  "skill_hash": "sha256:b7e8...",
  "signature": "MEUCIQ...",
  "signed_at": "2026-04-30T12:00:00Z",
  "schema_version": "2.1.0",
  "previous_hash": "sha256:a1b2c3...",
  "domain": "thirdkey.ai",
  "signer_kid": "thirdkey-2026-04",
  "file_manifest": { /* ... */ }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | string | Caller-supplied semver string identifying *this* version of the signed artifact. The value is opaque to SchemaPin (treat as a tag). |
| `previous_hash` | string | `sha256:<hex>` of the *prior* signed version's `skill_hash`. Forms a hash chain across successive signatures. |

Either field, when present, bumps `schemapin_version` to `"1.4"`. Documents without either field MAY remain `"1.3"`.

#### **18.2. Verifier Semantics — Informational**

`schema_version` and `previous_hash` are surfaced on `VerificationResult` (mirroring the same field names) but are **not** automatically enforced. Verifiers MUST:

- Copy `schema_version` from the signature onto the result when present.
- Copy `previous_hash` from the signature onto the result when present.

Verifiers MUST NOT:

- Reject a signature solely because `schema_version` is absent or unknown.
- Reject a signature solely because `previous_hash` doesn't match a record the verifier holds (callers do this explicitly via the chain-verification helper below).

#### **18.3. Chain Verification — Opt-In**

Implementations MUST provide a chain-verification helper (named `verify_chain` or the language-equivalent) that takes a `current` signature and a `previous` signature and returns success when:

```
current.previous_hash == previous.skill_hash
```

The helper MUST distinguish two failure modes for callers:

| Failure | Condition |
|---------|-----------|
| **No previous hash** | `current.previous_hash` is absent / empty. |
| **Mismatch** | Both fields present but unequal. The error MUST include both the expected and observed values. |

This is a pure-metadata check — no cryptography is re-evaluated. Both signatures MUST already be cryptographically verified independently for the chain check to be meaningful. Skipping the underlying signature verification would let an attacker forge a "chained" successor to any signature they choose.

#### **18.4. Operational Use**

A publisher MAINTAINING a chain SHOULD:

1. After signing v_n, record the resulting `skill_hash`.
2. When signing v_{n+1}, set `previous_hash = skill_hash_of_v_n`.
3. Distribute v_{n+1} alongside (or with the ability for verifiers to fetch) v_n.

A verifier APPLYING chain enforcement SHOULD maintain a per-tool `latest_known_hash` pinned alongside the TOFU public key. The reference SDKs provide this as `LineageStore` (`check_and_advance(tool_id, domain, signature)`), keyed by `tool_id@domain` and persisted as JSON. On encountering a new, already-verified `schemapin_version >= "1.4"` signature:

- `skill_hash` equals `latest_known_hash` → unchanged.
- `previous_hash` equals `latest_known_hash` and `schema_version` (when both carry one) increases numerically (`major.minor.patch`) → accept and roll forward.
- `previous_hash` absent or naming any other hash → reject (fork or rollback); an unauthorized substitution would either omit `previous_hash` or claim a hash the verifier has not seen. Operators MAY override after inspection, exactly like a TOFU key rotation.
- A legacy 1.3 document MUST be refused as a lineage anchor: its `skill_hash` and `previous_hash` are not covered by its signature.

#### **18.5. Backward Compatibility**

- v1.3 verifiers ignore both fields; signatures continue to verify.
- v1.4 signatures without `schema_version` or `previous_hash` behave identically to v1.3 signatures.
- The chain-verification helper is opt-in: callers who don't track lineage are unaffected.

### **19. Canonicalization Algorithm Identifier (v1.4)**

#### **19.1. Purpose**

The canonicalization rules of §4 are fixed across all v1.x signatures. To leave a forward-compatibility hook for a future v2.x canonicalization (e.g. RFC 8785 / JCS) without breaking existing v1.x signatures, v1.4 introduces an optional `canonicalization` field on `.schemapin.sig` documents (and a matching parameter on the verifier APIs).

The current and only supported value is `"schemapin-v1"` — the algorithm specified in §4. Future spec versions MAY introduce new identifiers; verifiers MUST reject any unrecognised identifier rather than silently fall back, so signers cannot trick a v1.x verifier into trusting a v2.x signing input.

#### **19.2. Wire Format**

```json
{
  "schemapin_version": "1.4",
  "canonicalization": "schemapin-v1",
  ...
}
```

The field is OPTIONAL. Absence is wire-equivalent to the implicit `"schemapin-v1"` default — signers who do not need to declare the algorithm SHOULD omit the field to keep v1.3-byte-identical wire output.

#### **19.3. Verifier Semantics**

Given a signature with `canonicalization == V`:

| Value of `V` | Verifier action |
|---|---|
| Absent (field missing) | Use `schemapin-v1` (the algorithm in §4). |
| `"schemapin-v1"` | Use `schemapin-v1`. |
| Anything else | **Hard failure** — surface as `CANONICALIZATION_UNSUPPORTED`. |

This check MUST execute before any cryptographic work (signature verification, public-key loading) so a misconfigured signer cannot induce timing-dependent failures.

#### **19.4. Backward Compatibility**

- v1.3 verifiers ignore unknown fields; v1.4 signatures with `canonicalization: "schemapin-v1"` continue to verify under v1.3.
- v1.4 signatures without `canonicalization` behave identically to v1.3 signatures.

### **20. A2A Verification Context (v1.4)**

#### **20.1. Purpose**

When tool schemas cross an A2A (Agent-to-Agent) trust boundary, verifiers need to scope verification to the intersection of *caller-trusted* domains and the *tool provider's* domain. SchemaPin v1.4 introduces `A2aVerificationContext` and `verify_schema_for_a2a` for this purpose. The semantics interoperate with AgentPin v0.3's `AllowedDomains` typed wrapper (AgentPin technical specification §4.11) so a SchemaPin verifier can directly consume the allow-list a caller's AgentPin credential carries.

#### **20.2. `A2aVerificationContext`**

```text
A2aVerificationContext {
  caller_agent_id:    String      // URN-style, matching AgentPin; informational
  delegation_depth:   u8          // 0 = direct caller
  originating_domain: String      // informational
  trusted_domains:    [String]    // see §20.3 convention
}
```

`caller_agent_id` and `originating_domain` are informational — verifiers do not validate them or use them in the scope check. Downstream policy engines (e.g. Symbiont) MAY correlate verification results with these fields for audit purposes.

#### **20.3. AllowedDomains Convention**

The `trusted_domains` list uses the same convention as AgentPin v0.3:

> **An empty `trusted_domains` list means *unrestricted*** — all provider domains are trusted. This is the opposite of the naïve set-theoretic interpretation but it matches the existing behaviour where an *omitted* allow-list permitted all domains.

A non-empty list restricts the verifier to provider domains that match an entry. Pattern matching follows the AgentPin §5.5 wildcard rule: a leading `*.` matches any subdomain (e.g. `*.client.com` matches `api.client.com` but NOT `client.com` itself).

#### **20.4. Verification Algorithm**

Given a context `C` and a normal verification request for provider domain `D`:

1. **Delegation-depth cap.** If `C.delegation_depth > 3`, fail with `A2A_SCOPE_VIOLATION`. The cap of 3 mirrors AgentPin's `max_delegation_depth` (AgentPin spec §4.3) and is exposed as the constant `A2A_MAX_DELEGATION_DEPTH`. Both specs MUST move this cap in lockstep.
2. **Standard verification.** Run the 7-step verification flow from §7 (including the §19 canonicalization check when applicable). If it fails, return that result unchanged — A2A scope is NOT a remedy for a failed cryptographic verification.
3. **Scope check.** When `C.trusted_domains` is non-empty, test whether `D` is allowed by the list under §20.3 semantics. If not, fail with `A2A_SCOPE_VIOLATION`. When `C.trusted_domains` is empty (unrestricted), this step is a no-op.

The scope check MUST use the `allows(trusted_domains, D)` primitive directly, NOT `allows(intersect(trusted_domains, [D]))`. The intersection helper documented in §20.5 has an edge case where two non-empty disjoint allow-lists intersect to `[]`, which the convention treats as "unrestricted" — using `intersect` here would silently bypass the scope check.

#### **20.5. AllowedDomains Helpers**

Each SDK MUST expose helpers matching the AgentPin v0.3 `AllowedDomains` API exactly:

| Operation | Behaviour |
|---|---|
| `is_unrestricted(list)` | `true` when `list` is empty. |
| `allows(list, domain)` | `true` when `list` is empty OR `domain` matches any entry (with `*.` wildcard expansion). |
| `intersect(lhs, rhs)` | `lhs ∩ rhs`, with two `unrestricted` short-circuits: `unrestricted ∩ X = X`, `X ∩ unrestricted = X`. Two non-empty disjoint inputs intersect to `[]` which, under the convention, then *also* means "unrestricted" — documented edge case from AgentPin spec §4.11.4. |

Implementations SHOULD copy these helpers from this section rather than taking a hard dependency on the AgentPin SDK, to keep SchemaPin self-contained for tool-integrity-only deployments. When both SDKs are linked, the AgentPin helpers can be substituted directly — the wire and in-memory shapes are identical.

#### **20.6. Backward Compatibility**

- v1.3 verifiers do not know about A2A context — they have no `verify_schema_for_a2a` entry point. Callers integrating with v1.3 verifiers fall back to the standard `verify_schema_offline` flow without scope enforcement.
- The `A2A_SCOPE_VIOLATION` error code is new in v1.4. Older verifiers cannot emit it.
- All v1.4 alpha.3 additions are additive — they introduce no changes to the signature on the wire (the new error code lives only in verifier output) so v1.4 alpha.1 / alpha.2 signatures verify identically under alpha.3 verifiers.

### **21. Trust Bundle Distribution (v1.4)**

#### **21.1. Purpose**

Allow a **bundle authority** to sign a trust bundle so it can be exchanged between agents over A2A without per-bundle out-of-band trust establishment. The receiving verifier authenticates the bundle against an **authority allow-list**: the authority's key fingerprint MUST be known to the verifier before a bundle from that `kid` is accepted. All fields are optional and additive — an unsigned bundle is unchanged from v1.2/v1.3.

**Risk statement.** A bundle carries its own authority public key, so the `kid` inside the bundle is attacker-chosen. Pinning the authority on first use by `kid` (the alpha.4 behavior) accepted any self-signed bundle under a fresh `kid`, which let a malicious A2A peer load keys for arbitrary domains. First-use trust therefore requires an explicit opt-in and MUST be surfaced to the operator like any other first-use key.

#### **21.2. Wire Format**

A signed trust bundle adds four OPTIONAL top-level fields:

```json
{
  "schemapin_bundle_version": "1.4",
  "documents": [ "..." ],
  "revocations": [ "..." ],
  "bundle_authority": {
    "kid": "schemapin-bundle-authority-2026",
    "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
  },
  "signed_at": "2026-05-15T00:00:00Z",
  "expires_at": "2099-01-01T00:00:00Z",
  "signature": "<base64 DER ECDSA P-256>"
}
```

The authority public key is carried as `public_key_pem` (consistent with discovery documents), making the bundle self-verifying. Signing sets `schemapin_bundle_version` to `"1.4"`.

#### **21.3. Signing Input**

The signature covers the `schemapin-v1` canonicalization (Section 4) of the bundle's **known fields** with the `signature` field set to the empty string `""`: `schemapin_bundle_version`, `created_at`, `documents` (each entry's `domain`, `schema_version`, `public_key_pem`, `revoked_keys` — always present, possibly empty — and, when present, `developer_name`, `contact`, `revocation_endpoint`), `revocations` (always present), `bundle_authority`, `signed_at` and `expires_at` when present. Unknown fields are not part of the signing input and are therefore unprotected. The signature is ECDSA P-256 with SHA-256 over the canonical bytes. All four SDKs MUST produce the identical byte string so a bundle signed by any SDK verifies in every other; `tests/cross-language/signed_bundle.json` (authority `kid` `schemapin-test-fixture-authority`, a test-only identity) is the reference.

#### **21.4. Operations**

- `sign_trust_bundle(bundle, private_key_pem, kid, signed_at, expires_at?)` — derive the authority public key, stamp `bundle_authority` / `signed_at` / `expires_at`, and write the signature.
- `seed_bundle_authority(store, kid, fingerprint)` / `seed_bundle_authority_from_pem(store, kid, public_key_pem)` — record an expected authority (the allow-list). The fingerprint is obtained out of band, for example from the authority domain's own `.well-known/schemapin.json` or DNS TXT record.
- `verify_trust_bundle(bundle, authority_pin_store, allow_first_use=false)`:
  1. Require `bundle_authority` and `signature` — else `BUNDLE_UNSIGNED`.
  2. Reject bundles with duplicate domain entries — `DISCOVERY_INVALID`.
  3. Reject when `expires_at` is present and in the past or not strict RFC 3339 — `BUNDLE_EXPIRED`.
  4. Look the authority's key fingerprint up by `kid`: a different seeded key is `KEY_PIN_MISMATCH`; an unknown `kid` is `BUNDLE_AUTHORITY_UNTRUSTED` unless `allow_first_use` is set.
  5. Verify the signature over the canonical bytes — failure is `SIGNATURE_INVALID`.
  6. Pin the authority on first use only after step 5, and return a structured result carrying `kid`, `fingerprint` and `first_use` so hosts can gate on it.
- `merge_trust_bundles(bundles, authority_precedence?)` — deduplicate `documents` and `revocations` by domain. The winner is chosen first by authority precedence (an ordered list of `kid`s; unlisted or absent authorities rank last) and then by the newer **parsed** RFC 3339 timestamp (`signed_at`, else `created_at`); unparseable timestamps rank oldest. Only verified bundles MUST be merged. Returns an UNSIGNED bundle to be re-signed before redistribution.
- `schemapin/trustBundle` JSON-RPC envelope helpers — `build_trust_bundle_request` / `build_trust_bundle_response` / `parse_trust_bundle_response`. The libraries define the message envelope; transport and the receiving pin-store update are the host application's responsibility.

#### **21.5. Backward Compatibility**

- Unsigned bundles omit all four fields and are byte-identical to pre-v1.4 bundles; existing resolvers ignore the new fields.
- The `BUNDLE_UNSIGNED`, `BUNDLE_EXPIRED` and `BUNDLE_AUTHORITY_UNTRUSTED` error codes are new in v1.4.
