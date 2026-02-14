# Changelog

All notable changes to the SchemaPin project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-02-14

### Added

#### SkillSigner — File-Based Skill Folder Signing & Verification (All Languages)

- **`skill` module (Rust, Python, JavaScript, Go)**: Deterministic directory canonicalization and cryptographic signing for AgentSkills (SKILL.md) folders.
- **`canonicalize_skill()`**: Recursively walks skill directory in sorted order, hashes each file as `SHA256(relative_path + content)`, produces deterministic root hash and file manifest. Skips `.schemapin.sig` and symlinks.
- **`parse_skill_name()`**: Extracts skill name from SKILL.md YAML frontmatter `name:` field, falls back to directory basename.
- **`sign_skill()`**: Signs a skill folder with an ECDSA P-256 private key. Writes `.schemapin.sig` JSON containing root hash, per-file manifest, signature, domain, signer KID, and timestamp.
- **`verify_skill_offline()`**: 7-step offline verification: load signature, validate discovery, extract key, check revocation, TOFU pin, canonicalize and compare, verify ECDSA signature.
- **`verify_skill_with_resolver()`**: Resolves discovery and revocation documents via `SchemaResolver` trait, then delegates to offline verification.
- **`load_signature()`**: Loads and parses `.schemapin.sig` JSON from a skill directory.
- **`detect_tampered_files()`**: Compares current file manifest against signed manifest, reports modified, added, and removed files.
- **`SkillSignature` struct**: Serializable signature document with `schemapin_version`, `skill_name`, `skill_hash`, `signature`, `signed_at`, `domain`, `signer_kid`, and `file_manifest`.

### Security

- Bumped `cryptography` dependency from 44.0.1/45.0.5 to 46.0.5 in Python and server packages.

## [1.2.0] - 2026-02-11

### Added

#### Rust Crate: Offline Verification, Trust Bundles, Resolver Abstraction

- **`error.rs`**: Unified `Error` type using `thiserror`, wrapping `crypto::Error` via `From`. Feature-gated `Http` variant. `ErrorCode` enum for structured verification results.
- **`types/discovery.rs`**: `WellKnownResponse` with optional `contact` and `revocation_endpoint` fields.
- **`types/revocation.rs`**: `RevocationDocument`, `RevokedKey`, `RevocationReason` enum (`KeyCompromise`, `Superseded`, `CessationOfOperation`, `PrivilegeWithdrawn`).
- **`types/pinning.rs`**: `PinnedTool`, `PinnedKey`, `TrustLevel` enum (`Tofu`, `Verified`, `Pinned`).
- **`types/bundle.rs`**: `SchemaPinTrustBundle`, `BundledDiscovery` with `find_discovery()` and `find_revocation()` methods.
- **`canonicalize.rs`**: JSON canonicalization with recursive key sorting and SHA-256 hashing. Functions: `canonicalize_schema()`, `hash_canonical()`, `canonicalize_and_hash()`.
- **`discovery.rs`**: URL construction, validation, builder. Functions: `construct_well_known_url()`, `validate_well_known_response()`, `build_well_known_response()`, `check_key_revocation()`, and fetch-gated `fetch_well_known()`.
- **`revocation.rs`**: Standalone revocation documents. Functions: `build_revocation_document()`, `add_revoked_key()`, `check_revocation()`, `check_revocation_combined()`, and fetch-gated `fetch_revocation_document()`.
- **`pinning.rs`**: TOFU key pinning keyed by `tool_id@domain`. `KeyPinStore` with `check_and_pin()`, `add_key()`, `get_tool()`, JSON serialization. `PinningResult` enum and `check_pinning()` wrapper.
- **`resolver.rs`**: `SchemaResolver` trait with 4 implementations: `WellKnownResolver` (fetch-gated), `LocalFileResolver`, `TrustBundleResolver`, `ChainResolver`. `AsyncSchemaResolver` trait (fetch-gated).
- **`verification.rs`**: `VerificationResult` struct. Functions: `verify_schema_offline()` (7-step flow), `verify_schema_with_resolver()`, and fetch-gated `verify_schema()`.

#### Python: Offline Verification, Trust Bundles, Resolver Abstraction

- **`revocation.py`**: `RevocationReason` enum, `RevokedKey`/`RevocationDocument` dataclasses. Functions: `build_revocation_document()`, `add_revoked_key()`, `check_revocation()`, `check_revocation_combined()`, `fetch_revocation_document()`.
- **`bundle.py`**: `SchemaPinTrustBundle` dataclass with `find_discovery()`, `find_revocation()`. Flattened `BundledDiscovery` format via dict merging.
- **`resolver.py`**: `SchemaResolver` ABC with 4 implementations: `WellKnownResolver`, `LocalFileResolver`, `TrustBundleResolver`, `ChainResolver`.
- **`verification.py`**: `ErrorCode` enum (8 codes), `KeyPinStore` in-memory pin store, `VerificationResult` dataclass. Functions: `verify_schema_offline()` (7-step flow), `verify_schema_with_resolver()`.
- **`utils.py`**: `create_well_known_response()` now accepts `revocation_endpoint` parameter, default `schema_version` changed to `"1.2"`.

#### JavaScript: Offline Verification, Trust Bundles, Resolver Abstraction

- **`revocation.js`**: `RevocationReason` constants. Functions: `buildRevocationDocument()`, `addRevokedKey()`, `checkRevocation()`, `checkRevocationCombined()`, `fetchRevocationDocument()`.
- **`bundle.js`**: Functions: `createTrustBundle()`, `createBundledDiscovery()`, `findDiscovery()`, `findRevocation()`, `parseTrustBundle()`. Flattened format via object spread.
- **`resolver.js`**: `SchemaResolver` base class with 4 implementations: `WellKnownResolver`, `LocalFileResolver`, `TrustBundleResolver`, `ChainResolver`.
- **`verification.js`**: `ErrorCode` constants, `KeyPinStore` class. Functions: `verifySchemaOffline()` (7-step flow), `verifySchemaWithResolver()`.
- **`utils.js`**: `createWellKnownResponse()` now accepts `revocationEndpoint` parameter, default `schemaVersion` changed to `"1.2"`.

#### Go: Offline Verification, Trust Bundles, Resolver Abstraction

- **`pkg/revocation/`**: `RevocationReason` type with constants, `RevokedKey`/`RevocationDocument` structs. Functions: `BuildRevocationDocument()`, `AddRevokedKey()`, `CheckRevocation()`, `CheckRevocationCombined()`, `FetchRevocationDocument()`.
- **`pkg/bundle/`**: `SchemaPinTrustBundle` struct with `FindDiscovery()`, `FindRevocation()`. `BundledDiscovery` with custom `MarshalJSON`/`UnmarshalJSON` for flattened format.
- **`pkg/resolver/`**: `SchemaResolver` interface with 4 implementations: `WellKnownResolver`, `LocalFileResolver`, `TrustBundleResolver`, `ChainResolver`.
- **`pkg/verification/`**: `ErrorCode` type (8 codes), `KeyPinStore` struct, `VerificationResult` struct. Functions: `VerifySchemaOffline()` (7-step flow), `VerifySchemaWithResolver()`.
- **`pkg/discovery/`**: Added `RevocationEndpoint` field to `WellKnownResponse`.
- **`pkg/utils/`**: `CreateWellKnownResponse()` now accepts `revocationEndpoint` parameter, default `schemaVersion` changed to `"1.2"`.

#### Specification Updates (v1.2)

- **Section 6**: Added `revocation_endpoint` and `contact` optional fields to `.well-known` response.
- **Section 8.5**: Standalone Revocation Document format.
- **Section 8.6**: Revocation Reasons (`key_compromise`, `superseded`, `cessation_of_operation`, `privilege_withdrawn`).
- **Section 8.7**: Combined Revocation Checking (simple list + standalone document).
- **Section 13**: Trust Bundles — format, use cases, `SchemaPinTrustBundle` structure.
- **Section 14**: Discovery Resolver — `SchemaResolver` abstraction, four implementations, `fetch` feature gate.
- **Section 15**: Offline Verification — `verify_schema_offline()` as core primitive, 7-step flow.
- **Section 12**: Updated backward compatibility note for v1.2.

### Changed

- **Rust**: Version bumped from 1.1.7 to 1.2.0
- **Rust**: Added `serde_json`, `thiserror`, `chrono` dependencies
- **Rust**: Added feature-gated `reqwest`, `tokio`, `async-trait` dependencies under `fetch` feature
- **Rust**: Added `tempfile` dev-dependency
- **Python**: Version bumped from 1.1.7 to 1.2.0
- **JavaScript**: Version bumped from 1.1.7 to 1.2.0
- **Go**: Version bumped from 1.1.7 to 1.2.0
- **All languages**: Default `schema_version` in `create_well_known_response()` changed from `"1.1"` to `"1.2"`

### Notes

- **Backward Compatible**: Existing core/crypto modules are untouched — no breaking changes in any language
- **No new dependencies**: Python uses stdlib `dataclasses`/`json`/`abc`, JS uses Node builtins, Go uses stdlib
- **Feature Flags** (Rust only): `default = []` (everything except HTTP). `fetch` enables HTTP-based discovery.
- 109 Python tests, 96 JavaScript tests, and all Go tests pass

## [1.1.7] - 2026-02-06

### Fixed

- **Go**: `NewSchemaVerificationWorkflow` now validates that pinning database path is not empty
- **Go**: Fixed all golangci-lint errors (unchecked error returns, gosimple, ineffassign)
- **Rust**: Fixed `cargo fmt` formatting issues in core and crypto modules
- **CI**: Fixed version consistency check in release-combined workflow (grep for `var Version` not `const Version`)
- **CI**: Fixed GitHub Release race condition where parallel release workflows would fail trying to create duplicate releases
- **CI**: Fixed duplicate `[dependencies]` section in crates.io release workflow test step

### Security

- **python-multipart**: Updated from 0.0.18 to 0.0.22 to fix HIGH severity CVE (dependabot alert #18)
- **js-yaml transitive CVE**: Eliminated by migrating ESLint from v8 to v9 flat config, removing the vulnerable transitive dependency (dependabot alert #17, MEDIUM severity)
- **brace-expansion**: Updated to fix low severity ReDoS vulnerability
- **cryptography**: Updated from 44.0.1 to 45.0.5 in server requirements to align with main Python package

### Changed

- **ESLint 9 migration**: Replaced legacy `.eslintrc.cjs` with `eslint.config.js` (flat config format) in JavaScript package
- **Version alignment**: Server and integration demo versions now aligned with core library versions

### Dependencies

- `python-multipart` 0.0.18 → 0.0.22 (server)
- `cryptography` 44.0.1 → 45.0.5 (server)
- `eslint` ^8.57.0 → ^9.0.0 (JavaScript devDependencies)
- Added `@eslint/js` ^9.0.0 and `globals` ^16.0.0 (JavaScript devDependencies)

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