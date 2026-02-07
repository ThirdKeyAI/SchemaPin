# Changelog

All notable changes to the SchemaPin project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.6] - 2026-02-06

### Security

- **python-multipart**: Updated from 0.0.18 to 0.0.22 in server requirements to fix HIGH severity CVE
- **cryptography**: Updated from 44.0.1 to 45.0.5 in server requirements

## [1.1.0] - 2025-01-07

### Added

#### Phase 1: Key Revocation System
- **Schema Version 1.1**: Enhanced `.well-known/schemapin.json` format with `revoked_keys` array
- **Key Revocation Support**: Automatic checking of revoked keys during verification
- **Backward Compatibility**: Full support for schema v1.0 endpoints
- **Revocation Validation**: Comprehensive validation of revoked key entries

#### Phase 2: Interactive Key Pinning
- **Interactive Pinning**: User prompts for key pinning decisions with detailed information
- **Domain Policies**: Configurable policies for automatic vs. interactive pinning
- **Enhanced UX**: Rich terminal output with colored status indicators and clear prompts
- **Key Management**: Advanced key pinning with metadata and policy enforcement

#### Phase 3: CLI Tools
- **schemapin-keygen**: Complete key generation tool with ECDSA/RSA support
- **schemapin-sign**: Schema signing tool with batch processing and metadata
- **schemapin-verify**: Verification tool with interactive pinning and discovery
- **Comprehensive Options**: Full CLI interface with extensive configuration options

#### Phase 4: Integration Demo and Production Server
- **Integration Demo**: Complete cross-language compatibility demonstration
- **Production Server**: Docker-ready `.well-known` endpoint server
- **Real-world Examples**: Practical usage scenarios and deployment guides
- **Cross-language Testing**: Validation of Python/JavaScript interoperability

#### Phase 5: Package Management and Distribution
- **Python Package**: Complete PyPI-ready package with modern packaging standards
- **JavaScript Package**: npm-ready package with comprehensive metadata
- **Build Scripts**: Automated building and testing infrastructure
- **Distribution Tools**: Publishing workflows and validation scripts

### Enhanced

#### Core Functionality
- **ECDSA P-256 Signatures**: Industry-standard cryptographic verification
- **Schema Canonicalization**: Deterministic JSON serialization for consistent hashing
- **Trust-On-First-Use (TOFU)**: Secure key pinning with user control
- **Public Key Discovery**: RFC 8615 compliant `.well-known` endpoint discovery

#### Security Features
- **Key Revocation**: Comprehensive revocation checking and validation
- **Signature Verification**: Robust cryptographic signature validation
- **Key Pinning Storage**: Secure local storage of pinned keys with metadata
- **Domain Validation**: Proper domain-based key association and verification

#### Developer Experience
- **High-level APIs**: Simple workflows for both developers and clients
- **Comprehensive Testing**: Full test suites with security validation
- **Rich Documentation**: Complete API documentation and usage examples
- **Cross-platform Support**: Works on Linux, macOS, and Windows

#### Package Quality
- **Modern Packaging**: Uses pyproject.toml and latest npm standards
- **Comprehensive Metadata**: Rich package information for discoverability
- **Development Tools**: Integrated linting, testing, and quality checks
- **Security Compliance**: Bandit security scanning and vulnerability checks

### Technical Specifications

#### Cryptographic Standards
- **Signature Algorithm**: ECDSA with P-256 curve (secp256r1)
- **Hash Algorithm**: SHA-256 for schema integrity
- **Key Format**: PEM encoding for interoperability
- **Signature Format**: Base64 encoding for transport

#### Protocol Compliance
- **RFC 8615**: `.well-known` URI specification compliance
- **JSON Schema**: Structured schema validation and canonicalization
- **HTTP Standards**: Proper HTTP headers and status codes
- **Cross-language**: Full Python and JavaScript compatibility

#### Package Standards
- **Python**: PEP 517/518 compliant with pyproject.toml
- **JavaScript**: Modern ES modules with comprehensive exports
- **Semantic Versioning**: Proper version management and compatibility
- **License Compliance**: MIT license with proper attribution

### Dependencies

#### Python Requirements
- `cryptography>=41.0.0` - ECDSA cryptographic operations
- `requests>=2.31.0` - HTTP client for key discovery
- Python 3.8+ support with type hints

#### JavaScript Requirements
- Node.js 18.0.0+ - Modern JavaScript runtime
- Zero external dependencies - Uses built-in crypto module
- ES modules with proper exports configuration

### Breaking Changes
- None - Full backward compatibility maintained

### Security Notes
- All cryptographic operations use industry-standard algorithms
- Key revocation checking prevents use of compromised keys
- Interactive pinning provides user control over trust decisions
- Secure storage of pinned keys with proper metadata

### Migration Guide
- Existing v1.0 implementations continue to work without changes
- New features are opt-in and backward compatible
- CLI tools provide migration assistance for existing workflows

## [1.0.0] - 2024-12-01

### Added
- Initial release of SchemaPin protocol
- Basic ECDSA P-256 signature verification
- Simple key pinning mechanism
- Python and JavaScript reference implementations
- Core cryptographic operations and schema canonicalization

---

For more details on any release, see the [GitHub releases page](https://github.com/thirdkey/schemapin/releases).