# SchemaPin Go Implementation

A Go implementation of the SchemaPin cryptographic protocol for ensuring the integrity and authenticity of tool schemas used by AI agents.

## Overview

SchemaPin prevents "MCP Rug Pull" attacks through digital signatures and Trust-On-First-Use (TOFU) key pinning. This Go implementation provides 100% protocol compatibility with the Python and JavaScript versions while following idiomatic Go patterns.

## Features

- **Cryptographic Security**: ECDSA P-256 digital signatures for schema integrity
- **Trust-On-First-Use**: Automatic key pinning with interactive user prompts
- **Key Discovery**: Automatic public key discovery via `.well-known/schemapin.json`
- **Key Revocation**: Support for revoked key lists and security warnings
- **CLI Tools**: Professional command-line tools for key generation, signing, and verification
- **Zero Dependencies**: Pure Go implementation with single binary deployment
- **Cross-Language Compatible**: Full interoperability with Python and JavaScript implementations
- **Interactive Pinning**: User prompts for key decisions with domain policies
- **Performance Optimized**: Fast ECDSA operations with efficient key storage

## Installation

### From Source

```bash
git clone https://github.com/ThirdKeyAi/schemapin.git
cd schemapin/go
make install
```

### Using Go Install

```bash
go install github.com/ThirdKeyAi/schemapin/go/cmd/...@latest
```

### Binary Releases

Download pre-built binaries from the [releases page](https://github.com/ThirdKeyAi/schemapin/releases).

## Quick Start

### 1. Generate Keys

```bash
# Generate ECDSA P-256 key pair
schemapin-keygen --type ecdsa --developer "Your Company" --contact "security@yourcompany.com" --well-known

# Output:
# ✓ Generated private key: private_key.pem
# ✓ Generated public key: public_key.pem
# ✓ Generated .well-known response: well_known.json
```

### 2. Sign a Schema

```bash
# Sign a JSON schema file
schemapin-sign --key private_key.pem --schema schema.json --output signed_schema.json

# Or sign inline
echo '{"name": "test", "type": "object"}' | schemapin-sign --key private_key.pem
```

### 3. Verify a Schema

```bash
# Verify with automatic key discovery
schemapin-verify --schema signed_schema.json --domain example.com --tool-id my-tool

# Verify with explicit public key
schemapin-verify --schema signed_schema.json --public-key public_key.pem

# Output:
# ✅ Schema signature is VALID
# 🔑 Key pinned for future use
# 📋 Developer: Your Company
```

## CLI Tools Reference

### schemapin-keygen

Generate ECDSA key pairs and .well-known responses.

```bash
schemapin-keygen [OPTIONS]

Options:
  --type string         Key type (ecdsa) (default "ecdsa")
  --developer string    Developer name for .well-known response
  --contact string      Contact email for .well-known response
  --output-dir string   Output directory (default ".")
  --private-key string  Private key filename (default "private_key.pem")
  --public-key string   Public key filename (default "public_key.pem")
  --well-known         Generate .well-known/schemapin.json response
  --revoked-keys string Comma-separated list of revoked key files
  --schema-version string Schema version (default "1.1")
```

### schemapin-sign

Sign JSON schemas with private keys.

```bash
schemapin-sign [OPTIONS]

Options:
  --key string          Private key file (required)
  --schema string       Schema file to sign (or use stdin)
  --output string       Output file (default stdout)
  --format string       Output format: json, compact (default "json")
```

### schemapin-verify

Verify signed schemas with automatic key discovery.

```bash
schemapin-verify [OPTIONS]

Options:
  --schema string       Signed schema file (required)
  --domain string       Domain for key discovery
  --tool-id string      Tool identifier for key pinning
  --public-key string   Explicit public key file (skips discovery)
  --db-path string      Key pinning database path (default "~/.schemapin/keys.db")
  --auto-pin           Automatically pin keys on first use
  --interactive        Enable interactive key pinning prompts
  --timeout duration   Discovery timeout (default 10s)
```

## API Documentation

### Core Packages

#### [`pkg/crypto`](pkg/crypto/crypto.go)

ECDSA key management and signature operations.

```go
// Generate key pair
keyManager := crypto.NewKeyManager()
privateKey, err := keyManager.GenerateKeypair()

// Export to PEM format
privateKeyPEM, err := keyManager.ExportPrivateKeyPEM(privateKey)
publicKeyPEM, err := keyManager.ExportPublicKeyPEM(&privateKey.PublicKey)

// Sign and verify
signatureManager := crypto.NewSignatureManager()
signature, err := signatureManager.SignHash(hash, privateKey)
valid := signatureManager.VerifySignature(hash, signature, &privateKey.PublicKey)
```

#### [`pkg/core`](pkg/core/core.go)

Schema canonicalization and hashing.

```go
// Canonicalize and hash schema
core := core.NewSchemaPinCore()
canonical, err := core.CanonicalizeSchema(schema)
hash := core.HashCanonical(canonical)

// Combined operation
hash, err := core.CanonicalizeAndHash(schema)
```

#### [`pkg/utils`](pkg/utils/utils.go)

High-level workflows for signing and verification.

```go
// Signing workflow
signingWorkflow, err := utils.NewSchemaSigningWorkflow(privateKeyPEM)
signature, err := signingWorkflow.SignSchema(schema)

// Verification workflow
verificationWorkflow, err := utils.NewSchemaVerificationWorkflow(dbPath)
result, err := verificationWorkflow.VerifySchema(ctx, schema, signature, toolID, domain, autoPin)
```

#### [`pkg/pinning`](pkg/pinning/pinning.go)

Key pinning with BoltDB storage.

```go
// Initialize key pinning
keyPinning, err := pinning.NewKeyPinning(dbPath, pinning.PinningModeInteractive, handler)

// Pin and verify keys
err = keyPinning.PinKey(toolID, publicKeyPEM, domain, developerName)
isPinned := keyPinning.IsKeyPinned(toolID)
pinnedKeys, err := keyPinning.ListPinnedKeys()
```

#### [`pkg/interactive`](pkg/interactive/interactive.go)

Interactive user prompts for key decisions.

```go
// Console handler
handler := interactive.NewConsoleInteractiveHandler()

// Callback handler
handler := interactive.NewCallbackInteractiveHandler(
    promptCallback,
    displayCallback,
    warningCallback,
)

// Prompt for key decisions
decision, err := handler.PromptUser(context)
```

#### [`pkg/discovery`](pkg/discovery/discovery.go)

Automatic public key discovery via .well-known endpoints.

```go
// Initialize discovery
discovery := discovery.NewPublicKeyDiscovery()

// Discover keys
publicKeyPEM, err := discovery.GetPublicKeyPEM(ctx, domain)
developerInfo, err := discovery.GetDeveloperInfo(ctx, domain)
isValid, err := discovery.ValidateKeyNotRevoked(ctx, publicKeyPEM, domain)
```

## Examples

### Developer Workflow

See [`examples/developer/main.go`](examples/developer/main.go) for a complete tool developer example:

```bash
cd examples/developer
go run main.go
```

This demonstrates:
- Key pair generation
- Schema creation and signing
- .well-known response generation
- File output for distribution

### Client Verification

See [`examples/client/main.go`](examples/client/main.go) for client verification:

```bash
cd examples/client
go run main.go
```

This demonstrates:
- Loading signed schemas
- Key discovery simulation
- TOFU key pinning
- Signature verification
- Invalid signature detection

### Interactive Pinning

See [`examples/interactive-demo/main.go`](examples/interactive-demo/main.go):

```bash
cd examples/interactive-demo
go run main.go
```

This demonstrates:
- Console interactive prompts
- Callback-based handlers
- Domain policies
- Key change scenarios

### Cross-Language Compatibility

See [`examples/cross-language-demo/main.go`](examples/cross-language-demo/main.go):

```bash
cd examples/cross-language-demo
go run main.go
```

This demonstrates:
- Verifying Python-generated signatures
- Verifying JavaScript-generated signatures
- Generating signatures for other languages

## Project Structure

```
go/
├── cmd/                    # CLI applications
│   ├── schemapin-keygen/   # Key generation tool
│   ├── schemapin-sign/     # Schema signing tool
│   └── schemapin-verify/   # Schema verification tool
├── pkg/                    # Public API packages
│   ├── core/              # Schema canonicalization
│   ├── crypto/            # ECDSA operations
│   ├── discovery/         # .well-known discovery
│   ├── pinning/           # Key pinning with BoltDB
│   ├── interactive/       # User interaction
│   └── utils/             # High-level workflows
├── internal/              # Private packages
│   └── version/           # Version information
├── examples/              # Usage examples
│   ├── developer/         # Tool developer workflow
│   ├── client/            # Client verification
│   ├── interactive-demo/  # Interactive pinning
│   └── cross-language-demo/ # Cross-language compatibility
├── tests/                 # Integration tests
└── docs/                  # Additional documentation
```

## Development

### Prerequisites

- Go 1.19 or later
- Make (optional, for convenience)

### Build

```bash
# Build all CLI tools
make build

# Build specific tool
go build -o bin/schemapin-keygen ./cmd/schemapin-keygen
```

### Test

```bash
# Run all tests
make test

# Run with coverage
go test -v -race -coverprofile=coverage.out ./...

# Run integration tests
go test -v ./tests/

# Run specific package tests
go test -v ./pkg/crypto/
```

### Lint

```bash
# Install golangci-lint
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Run linter
make lint
# or
golangci-lint run
```

### Performance Benchmarks

```bash
# Run benchmarks
go test -bench=. ./pkg/crypto/
go test -bench=. ./pkg/core/

# Example output:
# BenchmarkSignature-8     	    5000	    234567 ns/op
# BenchmarkVerification-8  	   10000	    123456 ns/op
```

## Performance

Performance characteristics on modern hardware:

| Operation | Time | Throughput |
|-----------|------|------------|
| Key Generation | ~2ms | 500 keys/sec |
| Schema Signing | ~1ms | 1000 sigs/sec |
| Signature Verification | ~0.5ms | 2000 verifs/sec |
| Schema Canonicalization | ~0.1ms | 10000 schemas/sec |

## Security Considerations

### Key Storage

- Private keys are stored in PEM format with 0600 permissions
- Key pinning database uses BoltDB with file-level locking
- No keys are stored in memory longer than necessary

### Cryptographic Details

- **Algorithm**: ECDSA with P-256 curve (secp256r1)
- **Hash Function**: SHA-256
- **Signature Format**: ASN.1 DER encoding for cross-language compatibility
- **Key Format**: PKCS#8 for private keys, PKIX for public keys

### Trust Model

- **TOFU (Trust On First Use)**: Keys are pinned on first encounter
- **Domain Policies**: Configure trust levels per domain
- **Key Revocation**: Support for revoked key lists in .well-known responses
- **Interactive Prompts**: User confirmation for key changes

## Troubleshooting

### Common Issues

#### "Key not found" errors

```bash
# Check if .well-known endpoint is accessible
curl https://yourdomain.com/.well-known/schemapin.json

# Verify domain in tool ID matches discovery domain
schemapin-verify --schema schema.json --domain yourdomain.com --tool-id yourdomain.com/tool
```

#### "Signature verification failed"

```bash
# Check schema format and canonicalization
schemapin-verify --schema schema.json --public-key public_key.pem --verbose

# Verify key format
openssl ec -in private_key.pem -text -noout
```

#### Database permission errors

```bash
# Check database directory permissions
ls -la ~/.schemapin/

# Reset database if corrupted
rm ~/.schemapin/keys.db
```

### Debug Mode

Enable debug logging:

```bash
export SCHEMAPIN_DEBUG=1
schemapin-verify --schema schema.json --domain example.com
```

### Cross-Language Issues

If signatures don't verify across languages:

1. Check schema canonicalization:
   ```bash
   # Compare canonical forms
   echo '{"b":2,"a":1}' | schemapin-sign --key key.pem --format compact
   ```

2. Verify key formats:
   ```bash
   # Keys should be identical across implementations
   diff go_public_key.pem python_public_key.pem
   ```

3. Test with known good signatures:
   ```bash
   # Use cross-language demo
   cd examples/cross-language-demo
   go run main.go
   ```

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make changes and add tests
4. Run tests: `make test`
5. Run linter: `make lint`
6. Commit changes: `git commit -m "Add feature"`
7. Push to branch: `git push origin feature-name`
8. Create a Pull Request

### Code Style

- Follow standard Go conventions
- Use `gofmt` for formatting
- Add godoc comments for public APIs
- Include tests for new functionality
- Update documentation for user-facing changes

## License

MIT License - see [LICENSE](../LICENSE) file for details.

## Related Projects

- [Python Implementation](../python/) - Reference implementation
- [JavaScript Implementation](../javascript/) - Browser and Node.js support
- [Integration Demo](../integration_demo/) - Cross-language testing
- [Production Server](../server/) - .well-known endpoint server

## Support

- [GitHub Issues](https://github.com/ThirdKeyAi/schemapin/issues) - Bug reports and feature requests
- [Discussions](https://github.com/ThirdKeyAi/schemapin/discussions) - Questions and community support
- [Security](mailto:security@thirdkey.ai) - Security vulnerability reports