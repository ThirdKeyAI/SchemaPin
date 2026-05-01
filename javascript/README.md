# SchemaPin JavaScript Implementation

A JavaScript/Node.js implementation of the SchemaPin protocol for cryptographic schema integrity verification of AI tools.

## Overview

SchemaPin provides cryptographic verification of AI tool schemas using ECDSA P-256 signatures and Trust-On-First-Use (TOFU) key pinning. This JavaScript implementation mirrors the functionality of the Python reference implementation.

## Features

- **ECDSA P-256 Cryptography**: Industry-standard elliptic curve signatures
- **Schema Canonicalization**: Deterministic JSON serialization for consistent hashing
- **Public Key Discovery**: **Automatic retrieval from `.well-known/schemapin.json` endpoints**
- **Key Pinning**: Trust-On-First-Use security model with persistent storage
- **Cross-Platform**: Works in Node.js environments
- **Zero Dependencies**: Uses only Node.js built-in modules

## Installation

### From npm (Recommended)

```bash
# Install latest stable version
npm install schemapin

# Install globally for CLI usage (if CLI tools are added)
npm install -g schemapin
```

### From Source (Development)

```bash
# Clone repository and install dependencies
git clone https://github.com/thirdkey/schemapin.git
cd schemapin/javascript
npm install
```

## Quick Start

### Tool Developer Workflow

```javascript
import { KeyManager, SchemaSigningWorkflow, createWellKnownResponse } from 'schemapin';

// 1. Generate key pair
const { privateKey, publicKey } = KeyManager.generateKeypair();

// 2. Sign your tool schema
const schema = {
    name: "calculate_sum",
    description: "Calculates the sum of two numbers",
    parameters: {
        type: "object",
        properties: {
            a: { type: "number", description: "First number" },
            b: { type: "number", description: "Second number" }
        },
        required: ["a", "b"]
    }
};

const signingWorkflow = new SchemaSigningWorkflow(privateKey);
const signature = signingWorkflow.signSchema(schema);

// 3. Create .well-known response
const wellKnownResponse = createWellKnownResponse(
    publicKey,
    "Your Organization",
    "contact@yourorg.com"
);

// Host wellKnownResponse at https://yourdomain.com/.well-known/schemapin.json
```

### Client Verification Workflow

```javascript
import { SchemaVerificationWorkflow } from 'schemapin';

const verificationWorkflow = new SchemaVerificationWorkflow();

// Verify schema with automatic key pinning
const result = await verificationWorkflow.verifySchema(
    schema,
    signature,
    "yourdomain.com/calculate_sum",
    "yourdomain.com",
    true // auto-pin on first use
);

if (result.valid) {
    console.log("✅ Schema signature is valid");
    if (result.first_use) {
        console.log("🔑 Key pinned for future use");
    }
} else {
    console.log("❌ Schema signature is invalid");
    console.log("Error:", result.error);
}
```

## API Reference

### Core Classes

#### `SchemaPinCore`
- `canonicalizeSchema(schema)` - Convert schema to canonical string format
- `hashCanonical(canonical)` - SHA-256 hash of canonical string
- `canonicalizeAndHash(schema)` - Combined canonicalization and hashing

#### `KeyManager`
- `generateKeypair()` - Generate new ECDSA P-256 key pair
- `exportPrivateKeyPem(privateKey)` - Export private key to PEM format
- `exportPublicKeyPem(publicKey)` - Export public key to PEM format
- `loadPrivateKeyPem(pemData)` - Load private key from PEM
- `loadPublicKeyPem(pemData)` - Load public key from PEM

#### `SignatureManager`
- `signHash(hashBytes, privateKey)` - Sign hash with private key
- `verifySignature(hashBytes, signature, publicKey)` - Verify signature
- `signSchemaHash(schemaHash, privateKey)` - Sign schema hash
- `verifySchemaSignature(schemaHash, signature, publicKey)` - Verify schema signature

#### `PublicKeyDiscovery`
- `fetchWellKnown(domain)` - Fetch .well-known/schemapin.json
- `getPublicKeyPem(domain)` - Get public key from domain
- `getDeveloperInfo(domain)` - Get developer information

#### `KeyPinning`
- `pinKey(toolId, publicKeyPem, domain, developerName)` - Pin public key
- `getPinnedKey(toolId)` - Get pinned key for tool
- `isKeyPinned(toolId)` - Check if key is pinned
- `listPinnedKeys()` - List all pinned keys
- `removePinnedKey(toolId)` - Remove pinned key

### High-Level Workflows

#### `SchemaSigningWorkflow`
```javascript
const workflow = new SchemaSigningWorkflow(privateKeyPem);
const signature = workflow.signSchema(schema);
```

#### `SchemaVerificationWorkflow`
```javascript
const workflow = new SchemaVerificationWorkflow();
const result = await workflow.verifySchema(schema, signature, toolId, domain, autoPin);
```

## v1.4-alpha (additive, optional)

v1.4-alpha.1 adds two opt-in features. Both are additive — v1.3 verifiers
ignore the new field and the new lookup, so signed skills remain
backward-compatible.

### Signature expiration (`expires_at`)

Use `signSkillWithOptions` to write an `expires_at` timestamp:

```javascript
import { signSkillWithOptions } from 'schemapin/skill';

signSkillWithOptions(skillDir, privateKeyPem, 'example.com', {
    expiresIn: 30 * 24 * 60 * 60 * 1000  // 30 days, in milliseconds
});
```

Verifiers past the expiration treat the result as **degraded, not failed**:
`result.valid` stays `true`, `result.expired` is set to `true`, and
`'signature_expired'` is appended to `result.warnings`.

### DNS TXT cross-verification

Publish a TXT record at `_schemapin.{domain}` of the form:

```
v=schemapin1; kid=acme-2026-01; fp=sha256:<lowercase-hex-of-public-key>
```

Then cross-check at verification time:

```javascript
import { fetchDnsTxt } from 'schemapin/dns';
import { verifySkillOfflineWithDns } from 'schemapin/skill';

const txt = await fetchDnsTxt('example.com');
const result = verifySkillOfflineWithDns(
    skillDir, discovery, null, null, null, 'tool-id', txt
);
```

A mismatch produces `result.error_code === 'domain_mismatch'`. A missing
record (`txt === null`) is a no-op. The DNS path uses Node's built-in
`node:dns/promises` — no external dependency is added.

Canonical guides:
- https://docs.schemapin.org/signature-expiration/
- https://docs.schemapin.org/dns-txt/

## Examples

Run the included examples:

```bash
# Tool developer workflow
node examples/developer.js

# Client verification workflow  
node examples/client.js
```

## Testing

```bash
npm test
```

## Security Considerations

- **Private Key Security**: Store private keys securely and never expose them
- **HTTPS Required**: Always use HTTPS for .well-known endpoint discovery
- **Key Pinning**: Review pinned keys periodically and verify authenticity
- **Signature Verification**: Always verify signatures before using tool schemas

## Cross-Language Compatibility

This JavaScript implementation is designed to be fully compatible with the Python reference implementation:

- Identical schema canonicalization results
- Compatible ECDSA P-256 signatures
- Same .well-known endpoint format
- Interoperable key formats (PEM)

## Node.js Version Support

- Node.js 18.0.0 or higher required
- Uses built-in `crypto` module for cryptographic operations
- ES modules (import/export) syntax

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Support

For issues and questions:
- GitHub Issues: [SchemaPin Repository](https://github.com/thirdkey/schemapin)
- Documentation: See TECHNICAL_SPECIFICATION.md
- Examples: Check the `examples/` directory