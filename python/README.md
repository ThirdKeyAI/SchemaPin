# SchemaPin Python Implementation

A Python implementation of the SchemaPin protocol for cryptographic schema integrity verification of AI tools.

## Overview

SchemaPin provides cryptographic verification of AI tool schemas using ECDSA P-256 signatures and Trust-On-First-Use (TOFU) key pinning. This Python implementation serves as the reference implementation for the protocol.

## Features

- **ECDSA P-256 Cryptography**: Industry-standard elliptic curve signatures
- **Schema Canonicalization**: Deterministic JSON serialization for consistent hashing
- **Public Key Discovery**: Automatic retrieval from `.well-known/schemapin.json` endpoints
- **Key Pinning**: Trust-On-First-Use security model with SQLite storage
- **High-Level Workflows**: Simple APIs for both developers and clients
- **Comprehensive Testing**: Full test suite with security validation

## Installation

### From PyPI (Recommended)

```bash
# Install latest stable version
pip install schemapin

# Install with development dependencies
pip install schemapin[dev]

# Install with testing dependencies only
pip install schemapin[test]
```

### From Source (Development)

```bash
# Clone repository and install in development mode
git clone https://github.com/thirdkey/schemapin.git
cd schemapin/python
pip install -e .[dev]
```

After installation, the following CLI tools will be available:
- `schemapin-keygen` - Generate cryptographic key pairs
- `schemapin-sign` - Sign JSON schemas
- `schemapin-verify` - Verify signed schemas

## CLI Tools

SchemaPin provides three command-line tools for common operations:

### Key Generation (`schemapin-keygen`)

Generate ECDSA or RSA key pairs with optional .well-known template:

```bash
# Generate ECDSA key pair with .well-known template
schemapin-keygen --type ecdsa --developer "Your Company" --well-known

# Generate RSA 4096-bit key pair
schemapin-keygen --type rsa --key-size 4096 --output-dir ./keys

# Generate keys in DER format
schemapin-keygen --type ecdsa --format der --prefix mykeys
```

### Schema Signing (`schemapin-sign`)

Sign JSON schema files with private keys:

```bash
# Sign a single schema
schemapin-sign --key private.pem --schema schema.json --output signed.json

# Sign with metadata
schemapin-sign --key private.pem --schema schema.json --developer "Your Company" --version "1.0"

# Batch sign multiple schemas
schemapin-sign --key private.pem --batch ./schemas/ --output-dir ./signed/

# Sign from stdin
echo '{"type": "object"}' | schemapin-sign --key private.pem --stdin
```

### Schema Verification (`schemapin-verify`)

Verify signed schemas with public keys or discovery:

```bash
# Verify with public key
schemapin-verify --schema signed.json --public-key public.pem

# Verify with domain discovery and interactive pinning
schemapin-verify --schema signed.json --domain example.com --tool-id my-tool --interactive

# Batch verify with auto-pinning
schemapin-verify --batch ./signed/ --domain example.com --auto-pin

# Verify from stdin with JSON output
echo '{"schema": {...}, "signature": "..."}' | schemapin-verify --stdin --public-key public.pem --json
```

### CLI Examples

Run the CLI examples script to see detailed usage patterns:

```bash
cd python/examples
python cli_usage_examples.py
```

## Quick Start

### Tool Developer Workflow

```python
from schemapin.utils import SchemaSigningWorkflow, create_well_known_response
from schemapin.crypto import KeyManager

# 1. Generate key pair
private_key, public_key = KeyManager.generate_keypair()
private_key_pem = KeyManager.export_private_key_pem(private_key)
public_key_pem = KeyManager.export_public_key_pem(public_key)

# 2. Sign your tool schema
schema = {
    "name": "calculate_sum",
    "description": "Calculates the sum of two numbers",
    "parameters": {
        "type": "object",
        "properties": {
            "a": {"type": "number", "description": "First number"},
            "b": {"type": "number", "description": "Second number"}
        },
        "required": ["a", "b"]
    }
}

signing_workflow = SchemaSigningWorkflow(private_key_pem)
signature = signing_workflow.sign_schema(schema)

# 3. Create .well-known response
well_known_response = create_well_known_response(
    public_key_pem,
    "Your Organization",
    "contact@yourorg.com"
)

# Host well_known_response at https://yourdomain.com/.well-known/schemapin.json
```

### Client Verification Workflow

```python
from schemapin.utils import SchemaVerificationWorkflow

verification_workflow = SchemaVerificationWorkflow()

# Verify schema with automatic key pinning
result = verification_workflow.verify_schema(
    schema,
    signature,
    "yourdomain.com/calculate_sum",
    "yourdomain.com",
    auto_pin=True
)

if result['valid']:
    print("✅ Schema signature is valid")
    if result['first_use']:
        print("🔑 Key pinned for future use")
else:
    print("❌ Schema signature is invalid")
    print("Error:", result['error'])
```

## API Reference

### Core Classes

#### `SchemaPinCore`
- `canonicalize_schema(schema)` - Convert schema to canonical string format
- `hash_canonical(canonical)` - SHA-256 hash of canonical string
- `canonicalize_and_hash(schema)` - Combined canonicalization and hashing

#### `KeyManager`
- `generate_keypair()` - Generate new ECDSA P-256 key pair
- `export_private_key_pem(private_key)` - Export private key to PEM format
- `export_public_key_pem(public_key)` - Export public key to PEM format
- `load_private_key_pem(pem_data)` - Load private key from PEM
- `load_public_key_pem(pem_data)` - Load public key from PEM

#### `SignatureManager`
- `sign_hash(hash_bytes, private_key)` - Sign hash with private key
- `verify_signature(hash_bytes, signature, public_key)` - Verify signature
- `sign_schema_hash(schema_hash, private_key)` - Sign schema hash
- `verify_schema_signature(schema_hash, signature, public_key)` - Verify schema signature

#### `PublicKeyDiscovery`
- `fetch_well_known(domain)` - Fetch .well-known/schemapin.json
- `get_public_key_pem(domain)` - Get public key from domain
- `get_developer_info(domain)` - Get developer information

#### `KeyPinning`
- `pin_key(tool_id, public_key_pem, domain, developer_name)` - Pin public key
- `get_pinned_key(tool_id)` - Get pinned key for tool
- `is_key_pinned(tool_id)` - Check if key is pinned
- `list_pinned_keys()` - List all pinned keys
- `remove_pinned_key(tool_id)` - Remove pinned key

### High-Level Workflows

#### `SchemaSigningWorkflow`
```python
workflow = SchemaSigningWorkflow(private_key_pem)
signature = workflow.sign_schema(schema)
```

#### `SchemaVerificationWorkflow`
```python
workflow = SchemaVerificationWorkflow()
result = workflow.verify_schema(schema, signature, tool_id, domain, auto_pin)
```

## Examples

Run the included examples:

```bash
# Tool developer workflow
cd python/examples
python tool_developer.py

# Client verification workflow  
python client_verification.py
```

## Testing

```bash
cd python
python -m pytest tests/ -v

# Run code quality checks
ruff check .
bandit -r . --exclude tests/
```

## Requirements

- Python 3.8 or higher
- cryptography library for ECDSA operations
- requests library for HTTP operations
- sqlite3 (built-in) for key storage

## Security Considerations

- **Private Key Security**: Store private keys securely and never expose them
- **HTTPS Required**: Always use HTTPS for .well-known endpoint discovery
- **Key Pinning**: Review pinned keys periodically and verify authenticity
- **Signature Verification**: Always verify signatures before using tool schemas

## Cross-Language Compatibility

This Python implementation is designed to be fully compatible with the JavaScript implementation:

- Identical schema canonicalization results
- Compatible ECDSA P-256 signatures
- Same .well-known endpoint format
- Interoperable key formats (PEM)

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