# SchemaPin: A Technical Specification

Version 1.1

Status: Draft

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

To ensure that a signature is valid across different platforms and environments, the tool schema's JSON object **MUST** be converted to a canonical string format before hashing and signing. The canonicalization process is as follows:

1. **Encoding:** The JSON string **MUST** be encoded using **UTF-8**.
2. **Whitespace:** All insignificant whitespace between JSON elements **MUST** be removed.
3. **Key Sorting:** The keys (names) in all JSON objects **MUST** be sorted lexicographically (alphabetically). This must be applied recursively to any nested objects.
4. **Serialization:** JSON data types MUST be serialized according to a strict, consistent format.

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

### **5. Signature and Key Formats**

- **Signature:** The generated signature **MUST** be a **detached signature**, encoded in **Base64**. It should be distributed as a separate file or field alongside the schema itself (e.g., in an `x-schema-signature` HTTP header or a `signature` field in a manifest file).

- **Public Key:** The developer's public key **MUST** be published in PEM format.

### **6. Public Key Discovery**

A client application needs a reliable way to find the correct public key for a given tool. This specification recommends a discovery mechanism based on the IETF's RFC 8615 for `.well-known` URIs.

A tool provider SHOULD host a JSON file at:

https://[tool_domain]/.well-known/schemapin.json

The contents of this file should be a JSON object specifying the public key:

```
{
  "schema_version": "1.1",
  "developer_name": "Example Corp Tools",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...etc...\n-----END PUBLIC KEY-----",
  "revoked_keys": [
    "sha256:abc123def456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
    "sha256:def456789abc123def456789abc123def456789abc123def456789abc123def4"
  ]
}
```

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
    
    c. Pin the Key: Upon successful first fetch, store the public key locally and associate it with the tool's identifier. This is the "pinning" step. The user should be prompted for confirmation before trusting a new key.
    
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
  "schema_version": "1.1",
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

### **9. Security Considerations**

- **Key Revocation:** Keys MUST be immediately revoked upon suspected compromise. Clients MUST check revocation status before each verification.
- **Key Compromise:** A developer whose private key is compromised must generate a new key pair and work with client applications to transition trust to the new key.
- **Transport Security:** All communications for public key discovery MUST use HTTPS to prevent man-in-the-middle attacks during the initial key fetch.
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

- **Schema Version:** This specification is version 1.1. The `schema_version` field in `.well-known` files indicates compatibility.
- **Backward Compatibility:** Version 1.1 clients MUST support version 1.0 endpoints for backward compatibility.
- **Future Versions:** Clients SHOULD gracefully handle unknown schema versions by falling back to the highest supported version.
- **Deprecation Policy:** Any breaking changes will be introduced in new major versions with appropriate migration guidance.