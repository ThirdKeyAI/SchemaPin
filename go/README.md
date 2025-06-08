# SchemaPin Go Implementation

A Go implementation of the SchemaPin cryptographic protocol for ensuring the integrity and authenticity of tool schemas used by AI agents.

## Overview

SchemaPin prevents "MCP Rug Pull" attacks through digital signatures and Trust-On-First-Use (TOFU) key pinning. This Go implementation provides 100% protocol compatibility with the Python and JavaScript versions while following idiomatic Go patterns.

## Features

- **Cryptographic Security**: ECDSA-based digital signatures for schema integrity
- **Trust-On-First-Use**: Automatic key pinning with interactive user prompts
- **Key Discovery**: Automatic public key discovery via `.well-known/schemapin.json`
- **Key Revocation**: Support for revoked key lists and security warnings
- **CLI Tools**: Professional command-line tools for key generation, signing, and verification
- **Zero Dependencies**: Pure Go implementation with single binary deployment
- **Cross-Language Compatible**: Full interoperability with Python and JavaScript implementations

## Installation

```bash
go install github.com/jascha/schemapin-go/cmd/...
```

## Quick Start

### Generate Keys
```bash
schemapin-keygen --type ecdsa --developer "Your Company" --well-known
```

### Sign a Schema
```bash
schemapin-sign --key private.pem --schema schema.json --output signed_schema.json
```

### Verify a Schema
```bash
schemapin-verify --schema signed_schema.json --domain example.com --tool-id my-tool
```

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
├── examples/              # Usage examples
└── tests/                 # Integration tests
```

## Development

### Build
```bash
make build
```

### Test
```bash
make test
```

### Lint
```bash
make lint
```

## Documentation

- [API Documentation](https://pkg.go.dev/github.com/jascha/schemapin-go)
- [CLI Reference](docs/cli.md)
- [Examples](examples/)

## License

MIT License - see [LICENSE](../LICENSE) file for details.