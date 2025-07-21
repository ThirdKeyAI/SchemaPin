# SchemaPin 🧷

A cryptographic protocol for ensuring the integrity and authenticity of tool schemas used by AI agents. SchemaPin prevents "MCP Rug Pull" attacks by enabling developers to cryptographically sign their tool schemas and allowing clients to verify that schemas have not been altered since publication.

## Table of Contents

- [About](#about)
  - [Core Security Guarantees](#core-security-guarantees)
  - [Broader Threat Protection](#broader-threat-protection)
  - [Real-World Attack Scenario: The "MCP Rug Pull"](#real-world-attack-scenario-the-mcp-rug-pull)
  - [Ecosystem and Trust Benefits](#ecosystem-and-trust-benefits)
- [Overview](#overview)
- [Features](#features)
- [Quick Start](#quick-start)
  - [For Tool Developers (Signing Schemas)](#for-tool-developers-signing-schemas)
  - [For AI Clients (Verifying Schemas)](#for-ai-clients-verifying-schemas)
- [Installation](#installation)
  - [From Package Repositories (Recommended)](#from-package-repositories-recommended)
  - [From Source (Development)](#from-source-development)
  - [Package Building](#package-building)
- [Examples](#examples)
- [Architecture](#architecture)
  - [Core Components](#core-components)
  - [Workflow](#workflow)
- [Security](#security)
  - [Cryptographic Standards](#cryptographic-standards)
  - [Schema Canonicalization](#schema-canonicalization)
  - [Key Pinning](#key-pinning)
- [Documentation](#documentation)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [GitHub Actions Workflows](#github-actions-workflows)
- [Contributing](#contributing)
- [License](#license)
- [Security Considerations](#security-considerations)
- [Contact](#contact)

## About

SchemaPin addresses critical security vulnerabilities in AI agent ecosystems by providing cryptographic guarantees for tool schema integrity and authenticity. As AI agents increasingly rely on external tools and services, ensuring these tools haven't been compromised becomes essential for maintaining system security and user trust.

### Core Security Guarantees

**Schema Integrity:** SchemaPin guarantees that tool schemas have not been altered maliciously or accidentally since publication, protecting against data corruption, misconfigured servers, or unauthorized modification. This ensures that the tool behavior your AI agent expects matches exactly what the tool developer intended.

**Authenticity:** Cryptographic signatures prove schema origin, ensuring schemas genuinely come from the claimed developer. This is critical for supply-chain security, preventing attackers from impersonating legitimate tool developers or injecting malicious schemas into trusted repositories.

### Broader Threat Protection

**Man-in-the-Middle (MITM) Attack Mitigation:** SchemaPin provides application-layer security that prevents schema tampering even if network connections are intercepted. This complements HTTPS transport security by ensuring that even if an attacker compromises the transport layer, they cannot forge valid schema signatures without access to the developer's private key.

**Compromised Infrastructure Defense:** Protection against scenarios where servers, CDNs, or repositories hosting schema files are hacked and schema files are replaced with malicious versions. Since attackers cannot forge signatures without the original developer's private keys, compromised infrastructure cannot be used to distribute malicious schemas that would pass verification.

### Real-World Attack Scenario: The "MCP Rug Pull"

Consider this concrete example: An AI agent uses a popular "file_manager" tool that initially provides legitimate file operations. After gaining widespread adoption, the tool's schema is maliciously updated to include a new "backup_to_cloud" function that secretly exfiltrates sensitive files to an attacker-controlled server. Without SchemaPin, AI agents would automatically trust and use this modified schema. With SchemaPin, the signature verification would fail, alerting users to the unauthorized modification and preventing the attack.

### Ecosystem and Trust Benefits

**Standardized Trust Mechanism:** SchemaPin provides a common, interoperable standard for verifying tools across different AI agent frameworks and programming languages. This creates a unified security foundation that benefits the entire AI ecosystem, regardless of the specific implementation or platform being used.

**Enabling Automated Governance:** The protocol allows enterprises and platforms to programmatically enforce security policies requiring valid signatures before tool execution. This enables automated compliance checking and reduces the manual overhead of security reviews while maintaining strong security guarantees.

**Trust on First Use (TOFU) Model:** Key pinning provides long-term security by protecting against future key substitution attacks. Once a developer's key is pinned, any attempt to use a different key for the same tool domain triggers security warnings, preventing attackers from compromising tools even if they gain control of the developer's infrastructure.

## Overview

SchemaPin provides a robust defense against supply-chain attacks where benign schemas are maliciously replaced after being approved. The protocol uses:

- **ECDSA P-256** signatures for cryptographic verification
- **SHA-256** hashing for schema integrity
- **Trust-On-First-Use (TOFU)** key pinning for ongoing security
- **RFC 8615** `.well-known` URIs for public key discovery

## Features

- ✅ **Strong Security**: ECDSA P-256 signatures with SHA-256 hashing
- ✅ **Cross-Language Support**: Python, JavaScript, Go, and Rust implementations
- ✅ **Simple Integration**: High-level APIs for both developers and clients
- ✅ **Key Pinning**: TOFU mechanism prevents key substitution attacks
- ✅ **Standard Compliance**: Follows RFC 8615 for key discovery
- ✅ **Comprehensive Testing**: Full test suite with security validation

```mermaid
flowchart TD
    A[Tool Developer] -->|Publishes| B["/.well-known/schemapin.json<br/>(Public Key + Revoked Keys)"]
    A -->|Signs| C["Tool Schema + Signature"]

    subgraph "AI Agent"
        D["Fetch Schema + Signature"]
        E["Fetch or Cache Public Key"]
        F["Check Key Revocation"]
        G["Verify Signature"]
        H{"Key Revoked?"}
        I{"Signature Valid?"}
        J{"Interactive Mode?"}
        K["Prompt User Decision"]
        L["Accept & Use Tool Schema"]
        M["Reject / Block Tool"]
        N["Pin Key (TOFU)"]
    end

    C --> D
    B --> E
    D --> G
    E --> F
    F --> H
    E --> G
    H -- Yes --> M
    H -- No --> G
    G --> I
    I -- No --> M
    I -- Yes --> J
    J -- Yes --> K
    J -- No --> N
    K --> L
    K --> M
    N --> L
```

## Quick Start

### For Tool Developers (Signing Schemas)

```python
from schemapin.utils import SchemaSigningWorkflow, create_well_known_response
from schemapin.crypto import KeyManager

# Generate key pair
private_key, public_key = KeyManager.generate_keypair()
private_key_pem = KeyManager.export_private_key_pem(private_key)

# Sign your tool schema
workflow = SchemaSigningWorkflow(private_key_pem)
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
signature = workflow.sign_schema(schema)

print(f"Signature: {signature}")
```

### For AI Clients (Verifying Schemas)

```python
from schemapin.utils import SchemaVerificationWorkflow

# Initialize verification
workflow = SchemaVerificationWorkflow()

# Verify schema (auto-pins key on first use)
result = workflow.verify_schema(
    schema=schema,
    signature_b64=signature,
    tool_id="example.com/calculate_sum",
    domain="example.com",
    auto_pin=True
)

if result['valid']:
    print("✅ Schema signature is valid")
    # Safe to use the tool
else:
    print("❌ Schema signature is invalid")
    # Reject the tool
```

## Installation

### From Package Repositories (Recommended)

#### Python (PyPI)

```bash
# Install from PyPI
pip install schemapin

# Or install with development dependencies
pip install schemapin[dev]
```

After installation, CLI tools will be available:
- `schemapin-keygen` - Generate cryptographic key pairs
- `schemapin-sign` - Sign JSON schemas
- `schemapin-verify` - Verify signed schemas

#### JavaScript/Node.js (npm)

```bash
# Install from npm
npm install schemapin

# Or install globally for CLI usage
npm install -g schemapin
```

#### Rust (Cargo)

```bash
# Add to your Cargo.toml
[dependencies]
schemapin = "1.1.4"

# Or install from git for latest development version
cargo add --git https://github.com/thirdkey/schemapin schemapin
```

#### Go

```bash
# Install CLI tools
go install github.com/ThirdKeyAi/schemapin/go/cmd/...@latest

# Or build from source
git clone https://github.com/thirdkey/schemapin.git
cd schemapin/go
make install
```

After installation, CLI tools will be available:
- `schemapin-keygen` - Generate cryptographic key pairs
- `schemapin-sign` - Sign JSON schemas
- `schemapin-verify` - Verify signed schemas

### From Source (Development)

```bash
# Clone repository
git clone https://github.com/thirdkey/schemapin.git
cd schemapin

# Set up Python environment
python3 -m venv .venv
source .venv/bin/activate

# Install Python package in development mode
cd python
pip install -e .[dev]

# Install JavaScript dependencies
cd ../javascript
npm install

# Build Go implementation
cd ../go
make build

# Build Rust implementation
cd ../rust
cargo build

# Run tests
cd ../python && python -m pytest tests/ -v
cd ../javascript && npm test
cd ../go && make test
cd ../rust && cargo test
```

### Package Building

```bash
# Build all packages
python scripts/build_packages.py

# Test packages
python scripts/test_packages.py

# Packages will be available in dist/
```

## Examples

### Complete Workflow Demo

```bash
# Run tool developer example
cd python/examples
python tool_developer.py

# Run client verification example
python client_verification.py
```

The examples demonstrate:
- Key pair generation
- Schema signing
- Public key publishing (`.well-known` format)
- Client verification with key pinning
- Invalid signature detection

## Architecture

### Core Components

- **[`SchemaPinCore`](python/schemapin/core.py)**: Schema canonicalization and hashing
- **[`KeyManager`](python/schemapin/crypto.py)**: ECDSA key generation and serialization
- **[`SignatureManager`](python/schemapin/crypto.py)**: Signature creation and verification
- **[`PublicKeyDiscovery`](python/schemapin/discovery.py)**: `.well-known` endpoint discovery
- **[`KeyPinning`](python/schemapin/pinning.py)**: TOFU key storage and management

### Workflow

```mermaid
graph LR
    A[Tool Schema] --> B[Canonicalize]
    B --> C[SHA-256 Hash]
    C --> D[ECDSA Sign]
    D --> E[Base64 Signature]
    
    F[Client] --> G[Fetch Schema + Signature]
    G --> H[Discover Public Key]
    H --> I[Check Key Revocation]
    I --> J[Verify Signature]
    J --> K{Valid & Not Revoked?}
    K -->|Yes| L[Interactive Pinning Check]
    L --> M[Use Tool]
    K -->|No| N[Reject Tool]
```

## Security

### Cryptographic Standards

- **Signature Algorithm**: ECDSA with P-256 curve (secp256r1)
- **Hash Algorithm**: SHA-256
- **Key Format**: PEM encoding
- **Signature Format**: Base64 encoding

### Schema Canonicalization

Schemas are canonicalized before signing to ensure consistent verification:

1. UTF-8 encoding
2. Remove insignificant whitespace
3. Sort JSON keys lexicographically (recursive)
4. Strict JSON serialization

### Key Pinning

SchemaPin uses Trust-On-First-Use (TOFU) key pinning:

- Keys are pinned on first successful verification
- Subsequent verifications use pinned keys
- Users are prompted before trusting new keys
- Pinned keys are stored securely with metadata

## Documentation

### Core Documentation
- **[Technical Specification](TECHNICAL_SPECIFICATION.md)** - Complete protocol details and cryptographic specifications
- **[Implementation Plan](IMPLEMENTATION_PLAN.md)** - Development roadmap and architecture decisions
- **[Enhancement Plan](SCHEMAPIN_ENHANCEMENT_PLAN.md)** - Latest feature enhancements and improvements
- **[Changelog](CHANGELOG.md)** - Version history and release notes

### Language-Specific Documentation
- **[Python Implementation](python/README.md)** - Python package documentation, CLI tools, and examples
- **[JavaScript Implementation](javascript/README.md)** - JavaScript/Node.js package documentation and examples
- **[Go Implementation](go/README.md)** - Go package documentation, CLI tools, and examples
- **[Rust Implementation](rust/README.md)** - Rust crate documentation and examples

### Integration and Deployment
- **[Integration Demo](integration_demo/README.md)** - Cross-language integration examples and test scenarios
- **[Production Server](server/README.md)** - Well-known endpoint server for production deployment
- **[GitHub Actions Workflows](.github/workflows/README.md)** - Automated release and CI/CD documentation

## Testing

```bash
# Run all tests
cd python
python -m pytest tests/ -v

# Run code quality checks
ruff check .
bandit -r . --exclude tests/

# Run examples
cd examples
python tool_developer.py
python client_verification.py
```

## GitHub Actions Workflows

SchemaPin includes automated CI/CD workflows for package releases:

### Available Workflows
- **[Release npm Package](.github/workflows/release-npm.yml)** - Automated npm package publishing
- **[Release PyPI Package](.github/workflows/release-pypi.yml)** - Automated PyPI package publishing
- **[Release Both Packages](.github/workflows/release-combined.yml)** - Coordinated dual-package release

### Workflow Features
- ✅ Version consistency validation between JavaScript and Python packages
- ✅ Comprehensive testing (unit tests, linting, security checks)
- ✅ Package installation testing in clean environments
- ✅ Test PyPI publishing before production release
- ✅ Automated GitHub release creation with changelogs
- ✅ Dry run support for testing workflows

### Usage
```bash
# Automatic release via git tags
git tag v1.2.0
git push origin v1.2.0

# Manual release via GitHub Actions UI
# Go to Actions tab → Select workflow → Run workflow
```

See **[GitHub Actions Documentation](.github/workflows/README.md)** for detailed setup and usage instructions.

## Project Structure

```
SchemaPin/
├── README.md                          # This file
├── TECHNICAL_SPECIFICATION.md         # Protocol specification
├── IMPLEMENTATION_PLAN.md             # Development plan
├── LICENSE                            # MIT License
├── .github/workflows/                 # GitHub Actions CI/CD
│   ├── release-npm.yml                # npm package release
│   ├── release-pypi.yml               # PyPI package release
│   ├── release-go.yml                 # Go package release
│   ├── release-combined.yml           # Multi-language package release
│   └── README.md                      # Workflow documentation
├── python/                            # Python reference implementation
│   ├── README.md                      # Python-specific documentation
│   ├── schemapin/                     # Core library
│   │   ├── __init__.py                # Package exports
│   │   ├── core.py                    # Schema canonicalization
│   │   ├── crypto.py                  # Cryptographic operations
│   │   ├── discovery.py               # Public key discovery
│   │   ├── pinning.py                 # Key pinning storage
│   │   └── utils.py                   # High-level workflows
│   ├── tests/                         # Test suite
│   ├── examples/                      # Usage examples
│   ├── requirements.txt               # Dependencies
│   └── setup.py                       # Package configuration
├── javascript/                        # JavaScript implementation
│   ├── README.md                      # JavaScript-specific documentation
│   ├── package.json                   # NPM package configuration
│   ├── src/                           # Core library
│   │   ├── index.js                   # Package exports
│   │   ├── core.js                    # Schema canonicalization
│   │   ├── crypto.js                  # Cryptographic operations
│   │   ├── discovery.js               # Public key discovery
│   │   ├── pinning.js                 # Key pinning storage
│   │   └── utils.js                   # High-level workflows
│   ├── tests/                         # Test suite
│   └── examples/                      # Usage examples
├── go/                                # Go implementation
│   ├── README.md                      # Go-specific documentation
│   ├── go.mod                         # Go module configuration
│   ├── cmd/                           # CLI applications
│   │   ├── schemapin-keygen/          # Key generation tool
│   │   ├── schemapin-sign/            # Schema signing tool
│   │   └── schemapin-verify/          # Schema verification tool
│   ├── pkg/                           # Public API packages
│   │   ├── core/                      # Schema canonicalization
│   │   ├── crypto/                    # Cryptographic operations
│   │   ├── discovery/                 # Public key discovery
│   │   ├── pinning/                   # Key pinning storage
│   │   ├── interactive/               # User interaction
│   │   └── utils/                     # High-level workflows
│   ├── examples/                      # Usage examples
│   └── tests/                         # Integration tests
├── rust/                              # Rust implementation
│   ├── README.md                      # Rust-specific documentation
│   ├── Cargo.toml                     # Rust crate configuration
│   ├── src/                           # Core library
│   │   ├── lib.rs                     # Crate root and exports
│   │   ├── core.rs                    # Schema canonicalization
│   │   ├── crypto.rs                  # Cryptographic operations
│   │   └── main.rs                    # CLI application
│   ├── examples/                      # Usage examples
│   └── tests/                         # Test suite
├── integration_demo/                  # Cross-language integration
├── server/                            # Production .well-known server
└── scripts/                           # Build and deployment scripts
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and quality checks
5. Submit a pull request

## License

MIT License - see [`LICENSE`](LICENSE) file for details.

## Security Considerations

- Keep private keys secure and never commit them to version control
- Verify signatures before using any tool schema
- Pin keys on first use and validate key changes
- Use HTTPS for `.well-known` endpoint discovery
- Consider certificate pinning for additional security

## Contact

- **Author**: Jascha Wanger / [ThirdKey.ai](https://thirdkey.ai)
- **Email**: jascha@thirdkey.ai
- **Repository**: https://github.com/thirdkey/schemapin

---

**SchemaPin**: Cryptographic integrity for AI tool schemas. Prevent MCP Rug Pull attacks with digital signatures and key pinning.
