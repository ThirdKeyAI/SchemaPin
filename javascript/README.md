# SchemaPin JavaScript Implementation

A JavaScript/Node.js implementation of the SchemaPin protocol for cryptographic schema integrity verification of AI tools.

## Overview

SchemaPin provides cryptographic verification of AI tool schemas using ECDSA P-256 signatures and Trust-On-First-Use (TOFU) key pinning. This JavaScript implementation mirrors the functionality of the Python reference implementation.

## Features

- **ECDSA P-256 Cryptography**: Industry-standard elliptic curve signatures
- **Schema Canonicalization**: Deterministic JSON serialization for consistent hashing
- **Public Key Discovery**: Automatic retrieval from `.well-known/schemapin.json` endpoints
- **Key Pinning**: Trust-On-First-Use security model with persistent storage
- **Cross-Platform**: Works in Node.js environments
- **Zero Dependencies**: Uses only Node.js built-in modules

## Installation

```bash
npm install schemapin
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