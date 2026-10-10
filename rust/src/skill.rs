//! Skill directory signing and verification.
//!
//! Mirrors the Python `SkillSigner` class: same canonicalization algorithm,
//! same `.schemapin.sig` format, cross-language interop.
//!
//! # Wire formats
//!
//! `schemapin_version: "1.4"` (the default for every new signature):
//!
//! - The directory is canonicalized with [`canonicalize_skill`] (skill
//!   canonicalization v2, spec section 4b): every entry is hashed as
//!   `SHA-256("f" || be64(len(path)) || path || be64(len(content)) || content)`
//!   and the root hash is SHA-256 over `be64(len(path)) || path || digest` for
//!   every entry in code-point path order. Symlinks are rejected.
//! - `skill_hash` is `"sha256:" + hex(root_hash)`.
//! - The signature covers the **entire signature document**: the document is
//!   built with `signature: ""`, canonicalized with `schemapin-v1` and signed
//!   as `ECDSA-P256(SHA-256(canonical_bytes))`. `expires_at`, `schema_version`,
//!   `previous_hash`, `canonicalization`, `domain`, `skill_name`, `signer_kid`,
//!   `signed_at` and `file_manifest` are therefore all integrity-protected.
//!
//! `schemapin_version: "1.3"` (legacy, verify-only):
//!
//! - Entries hashed as `SHA-256(path || content)`, root hash SHA-256 of the
//!   concatenated hex digests, symlinks silently skipped, and the signature
//!   covers only the 32-byte root hash. None of the metadata fields are
//!   signed; verifiers surface a `legacy_signature_format` warning.
//!
//! Verification is fail-closed on expiration and on domain mismatch.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use p256::pkcs8::{DecodePrivateKey, EncodePublicKey};

use crate::canonicalize::canonicalize_schema;
use crate::crypto;
use crate::discovery::validate_well_known_response;
use crate::domain::validate_domain;
use crate::error::{Error, ErrorCode};
use crate::pinning::{KeyPinStore, PinningResult};
use crate::resolver::SchemaResolver;
use crate::revocation::check_revocation_combined;
use crate::types::discovery::WellKnownResponse;
use crate::types::revocation::RevocationDocument;
use crate::verification::{KeyPinningStatus, ResolverOptions, VerificationResult};

/// `schemapin_version` written on every new signature (signed-document format).
pub const SCHEMAPIN_VERSION: &str = "1.4";
/// Legacy root-hash-only format; accepted on verification, never written.
pub const SCHEMAPIN_VERSION_LEGACY: &str = "1.3";

/// Caps enforced by [`canonicalize_skill`].
pub const MAX_SKILL_FILES: usize = 10_000;
pub const MAX_SKILL_TOTAL_BYTES: u64 = 256 * 1024 * 1024;

const SIGNATURE_FILENAME: &str = ".schemapin.sig";

/// Signature metadata written to `.schemapin.sig`.
///
/// Optional v1.4 fields:
/// - `expires_at` — verification fails with `SIGNATURE_EXPIRED` past this unless
///   the caller allows expired signatures (see [`VerifyOptions`]).
/// - `schema_version` — caller-supplied semver string identifying *this* version of
///   the signed artifact (e.g. `"2.1.0"`). Returned via [`crate::verification::VerificationResult`]
///   so consumers can apply their own version policy.
/// - `previous_hash` — SHA-256 hash (`sha256:<hex>`) of the *prior* signed version's
///   `skill_hash`, forming a hash chain. Use [`verify_chain`] to confirm a new signature
///   descends from a specific prior signature.
/// - `canonicalization` — algorithm identifier naming the canonicalization used to
///   produce the signing input. Absence is equivalent to `"schemapin-v1"`. Verifiers
///   MUST reject any other value as `CANONICALIZATION_UNSUPPORTED`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillSignature {
    pub schemapin_version: String,
    pub skill_name: String,
    pub skill_hash: String,
    pub signature: String,
    pub signed_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canonicalization: Option<String>,
    pub domain: String,
    pub signer_kid: String,
    pub file_manifest: BTreeMap<String, String>,
}

/// Result of comparing two file manifests.
#[derive(Debug, Clone, Default)]
pub struct TamperedFiles {
    pub modified: Vec<String>,
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

fn canon_err(msg: String) -> Error {
    Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, msg))
}

fn be64(n: usize) -> [u8; 8] {
    (n as u64).to_be_bytes()
}

/// Recursively walk a directory and compute the v2 root hash (spec section 4b).
///
/// 1. Walk the tree; directories are not entries. The top-level
///    `.schemapin.sig` is excluded.
/// 2. Any symlink (file or directory) or non-regular file aborts
///    canonicalization -- unsigned content must not be reachable from a
///    signed skill.
/// 3. Paths are relative, forward-slash separated, UTF-8, sorted by code point.
/// 4. Per entry: `SHA-256(0x66 || be64(len(path)) || path || be64(len(content)) || content)`.
/// 5. Root: SHA-256 over `be64(len(path)) || path || entry_digest` for every
///    entry in sorted order.
///
/// Returns `(root_hash_bytes, manifest)` where each manifest entry maps a
/// forward-slash relative path to `"sha256:<hex>"`.
pub fn canonicalize_skill(skill_dir: &Path) -> Result<(Vec<u8>, BTreeMap<String, String>), Error> {
    if !skill_dir.is_dir() {
        return Err(canon_err(format!(
            "not a directory: {}",
            skill_dir.display()
        )));
    }
    let mut entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut total: u64 = 0;
    walk_v2(skill_dir, skill_dir, &mut entries, &mut total)?;

    if entries.is_empty() {
        return Err(canon_err("skill directory contains no files".to_string()));
    }

    let mut root = Sha256::new();
    let mut manifest = BTreeMap::new();
    for (path, digest) in &entries {
        root.update(be64(path.len()));
        root.update(path.as_bytes());
        root.update(digest);
        manifest.insert(path.clone(), format!("sha256:{}", hex::encode(digest)));
    }
    Ok((root.finalize().to_vec(), manifest))
}

fn walk_v2(
    base: &Path,
    dir: &Path,
    entries: &mut BTreeMap<String, Vec<u8>>,
    total: &mut u64,
) -> Result<(), Error> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)?;
        if meta.is_symlink() {
            return Err(canon_err(format!(
                "symlink not permitted in skill directory: {}",
                path.display()
            )));
        }
        if meta.is_dir() {
            walk_v2(base, &path, entries, total)?;
            continue;
        }
        if !meta.is_file() {
            return Err(canon_err(format!(
                "non-regular file in skill directory: {}",
                path.display()
            )));
        }
        if dir == base && entry.file_name() == SIGNATURE_FILENAME {
            continue;
        }
        let rel = path
            .strip_prefix(base)
            .map_err(|e| canon_err(e.to_string()))?;
        let mut parts = Vec::new();
        for component in rel.components() {
            let part = component
                .as_os_str()
                .to_str()
                .ok_or_else(|| canon_err(format!("path is not valid UTF-8: {}", path.display())))?;
            parts.push(part.to_string());
        }
        let rel_str = parts.join("/");

        let file_bytes = fs::read(&path)?;
        *total += file_bytes.len() as u64;
        if entries.len() + 1 > MAX_SKILL_FILES {
            return Err(canon_err(format!(
                "skill exceeds {} files",
                MAX_SKILL_FILES
            )));
        }
        if *total > MAX_SKILL_TOTAL_BYTES {
            return Err(canon_err(format!(
                "skill exceeds {} bytes",
                MAX_SKILL_TOTAL_BYTES
            )));
        }
        let mut hasher = Sha256::new();
        hasher.update(b"f");
        hasher.update(be64(rel_str.len()));
        hasher.update(rel_str.as_bytes());
        hasher.update(be64(file_bytes.len()));
        hasher.update(&file_bytes);
        entries.insert(rel_str, hasher.finalize().to_vec());
    }
    Ok(())
}

/// Legacy (`schemapin_version: "1.3"`) skill canonicalization.
///
/// Kept only so that pre-1.4 signatures still verify. Per-file digest is
/// `SHA-256(path || content)`, the root hash is SHA-256 of the concatenated
/// hex digests, symlinks are skipped and `.schemapin.sig` is excluded at any
/// depth. Do not use for new signatures.
pub fn canonicalize_skill_v1(
    skill_dir: &Path,
) -> Result<(Vec<u8>, BTreeMap<String, String>), Error> {
    let mut manifest = BTreeMap::new();
    walk_v1(skill_dir, skill_dir, &mut manifest)?;

    if manifest.is_empty() {
        return Err(canon_err("skill directory contains no files".to_string()));
    }

    let joined: String = manifest
        .values()
        .map(|v| v.strip_prefix("sha256:").unwrap_or(v))
        .collect::<Vec<_>>()
        .join("");

    let root_hash = Sha256::digest(joined.as_bytes()).to_vec();
    Ok((root_hash, manifest))
}

fn walk_v1(base: &Path, dir: &Path, manifest: &mut BTreeMap<String, String>) -> Result<(), Error> {
    let mut entries: Vec<fs::DirEntry> = fs::read_dir(dir)?.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)?;
        if meta.is_symlink() {
            continue;
        }
        if meta.is_dir() {
            walk_v1(base, &path, manifest)?;
        } else if meta.is_file() {
            if entry.file_name() == SIGNATURE_FILENAME {
                continue;
            }
            let rel = path
                .strip_prefix(base)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            let rel_str = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");

            let file_bytes = fs::read(&path)?;
            let mut hasher = Sha256::new();
            hasher.update(rel_str.as_bytes());
            hasher.update(&file_bytes);
            manifest.insert(
                rel_str,
                format!("sha256:{}", hex::encode(hasher.finalize())),
            );
        }
    }
    Ok(())
}

/// Extract the skill name from `SKILL.md` frontmatter, falling back to the
/// directory basename.
pub fn parse_skill_name(skill_dir: &Path) -> String {
    let skill_md = skill_dir.join("SKILL.md");
    if let Ok(text) = fs::read_to_string(&skill_md) {
        if let Some(name) = extract_frontmatter_name(&text) {
            return name;
        }
    }
    skill_dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".to_string())
}

/// String-based frontmatter `name:` extraction (no regex).
fn extract_frontmatter_name(text: &str) -> Option<String> {
    let text = text.trim_start_matches('\u{feff}');
    if !text.starts_with("---") {
        return None;
    }
    let after_open = &text[3..];
    let after_open = after_open.strip_prefix('\r').unwrap_or(after_open);
    let after_open = after_open.strip_prefix('\n')?;
    let close_idx = after_open.find("\n---")?;
    let frontmatter = &after_open[..close_idx];

    for line in frontmatter.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("name:") {
            let val = rest.trim();
            let val = val
                .strip_prefix('\'')
                .and_then(|v| v.strip_suffix('\''))
                .or_else(|| val.strip_prefix('"').and_then(|v| v.strip_suffix('"')))
                .unwrap_or(val);
            let val = val.trim();
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
}

/// Read and parse the `.schemapin.sig` file from a skill directory.
pub fn load_signature(skill_dir: &Path) -> Result<SkillSignature, Error> {
    let sig_path = skill_dir.join(SIGNATURE_FILENAME);
    let data = fs::read_to_string(&sig_path)?;
    let sig: SkillSignature = serde_json::from_str(&data)?;
    Ok(sig)
}

/// Build the canonical bytes a v1.4 signature covers.
///
/// Takes the known signature fields (unknown fields are ignored and therefore
/// unprotected), drops absent / empty optional fields, forces `signature` to
/// `""` and canonicalizes with `schemapin-v1`.
pub fn signing_input(sig: &SkillSignature) -> Result<Vec<u8>, Error> {
    let mut doc = Map::new();
    for (key, value) in [
        ("schemapin_version", &sig.schemapin_version),
        ("skill_name", &sig.skill_name),
        ("skill_hash", &sig.skill_hash),
        ("signed_at", &sig.signed_at),
        ("domain", &sig.domain),
        ("signer_kid", &sig.signer_kid),
    ] {
        if value.is_empty() {
            return Err(Error::Verification {
                code: ErrorCode::SignatureInvalid,
                message: format!("signature document field {:?} is missing", key),
            });
        }
        doc.insert(key.to_string(), Value::String(value.clone()));
    }
    let manifest: Map<String, Value> = sig
        .file_manifest
        .iter()
        .map(|(k, v)| (k.clone(), Value::String(v.clone())))
        .collect();
    doc.insert("file_manifest".to_string(), Value::Object(manifest));
    for (key, value) in [
        ("expires_at", &sig.expires_at),
        ("schema_version", &sig.schema_version),
        ("previous_hash", &sig.previous_hash),
        ("canonicalization", &sig.canonicalization),
    ] {
        if let Some(v) = value {
            if !v.is_empty() {
                doc.insert(key.to_string(), Value::String(v.clone()));
            }
        }
    }
    doc.insert("signature".to_string(), Value::String(String::new()));
    Ok(canonicalize_schema(&Value::Object(doc))?.into_bytes())
}

/// Optional sign-time parameters for [`sign_skill_with_options`].
///
/// Builder-style: all fields default to `None`.
#[derive(Debug, Default, Clone)]
pub struct SignOptions<'a> {
    /// Override the signer key id (KID). Defaults to the discovery fingerprint of the public key.
    pub signer_kid: Option<&'a str>,
    /// Override the skill name. Defaults to the SKILL.md frontmatter `name:` or directory basename.
    pub skill_name: Option<&'a str>,
    /// Time-to-live for the signature. When set, an `expires_at` field is written
    /// (a negative duration yields an already-expired signature, useful for tests).
    pub expires_in: Option<chrono::Duration>,
    /// Caller-supplied semver string identifying *this* version of the signed artifact.
    pub schema_version: Option<&'a str>,
    /// `sha256:<hex>` hash of the *prior* signed version's `skill_hash`, forming a chain.
    pub previous_hash: Option<&'a str>,
    /// Canonicalization algorithm identifier to record in the signature.
    pub canonicalization: Option<&'a str>,
}

impl<'a> SignOptions<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_signer_kid(mut self, kid: &'a str) -> Self {
        self.signer_kid = Some(kid);
        self
    }

    pub fn with_skill_name(mut self, name: &'a str) -> Self {
        self.skill_name = Some(name);
        self
    }

    pub fn with_expires_in(mut self, ttl: chrono::Duration) -> Self {
        self.expires_in = Some(ttl);
        self
    }

    pub fn with_schema_version(mut self, version: &'a str) -> Self {
        self.schema_version = Some(version);
        self
    }

    pub fn with_previous_hash(mut self, hash: &'a str) -> Self {
        self.previous_hash = Some(hash);
        self
    }

    /// Declare the canonicalization algorithm identifier on the wire.
    pub fn with_canonicalization(mut self, algorithm: &'a str) -> Self {
        self.canonicalization = Some(algorithm);
        self
    }
}

/// Policy knobs for [`verify_skill_offline_with_options`].
#[derive(Debug, Default, Clone)]
pub struct VerifyOptions<'a> {
    /// Bind the skill to an expected domain: the signature's `domain` must
    /// equal it (`DOMAIN_MISMATCH` otherwise). Pass it whenever you know which
    /// domain the discovery document belongs to -- the signature's own
    /// `domain` field is display-only. When `None` the signature's domain is
    /// used and a `domain_unbound` warning is surfaced.
    pub domain: Option<&'a str>,
    /// Pin-store key; defaults to the signature's `skill_name`.
    pub tool_id: Option<&'a str>,
    /// Accept expired signatures (degraded) instead of failing with
    /// `SIGNATURE_EXPIRED`.
    pub allow_expired: bool,
}

/// Sign a skill directory and write `.schemapin.sig`.
///
/// Convenience wrapper over [`sign_skill_with_options`].
pub fn sign_skill(
    skill_dir: &Path,
    private_key_pem: &str,
    domain: &str,
    signer_kid: Option<&str>,
    skill_name: Option<&str>,
) -> Result<SkillSignature, Error> {
    sign_skill_with_options(
        skill_dir,
        private_key_pem,
        domain,
        SignOptions {
            signer_kid,
            skill_name,
            ..SignOptions::default()
        },
    )
}

/// Sign a skill directory and write a v1.4 signature document.
///
/// The whole document (including `expires_at` when `options.expires_in` is
/// set) is covered by the signature. See the module documentation.
pub fn sign_skill_with_options(
    skill_dir: &Path,
    private_key_pem: &str,
    domain: &str,
    options: SignOptions<'_>,
) -> Result<SkillSignature, Error> {
    let domain = validate_domain(domain)?;
    let (root_hash, manifest) = canonicalize_skill(skill_dir)?;

    let name = match options.skill_name {
        Some(n) => n.to_string(),
        None => parse_skill_name(skill_dir),
    };

    let kid = match options.signer_kid {
        Some(k) => k.to_string(),
        None => {
            let secret = p256::SecretKey::from_pkcs8_pem(private_key_pem)
                .map_err(|e| Error::Pkcs8(e.to_string()))?;
            let public = secret.public_key();
            let pem = public
                .to_public_key_pem(p256::pkcs8::LineEnding::LF)
                .map_err(|e| Error::Spki(e.to_string()))?;
            crypto::calculate_key_id(&pem)?
        }
    };

    let now = chrono::Utc::now();
    let expires_at = options
        .expires_in
        .map(|ttl| (now + ttl).to_rfc3339_opts(chrono::SecondsFormat::Secs, true));

    let mut sig_doc = SkillSignature {
        schemapin_version: SCHEMAPIN_VERSION.to_string(),
        skill_name: name,
        skill_hash: format!("sha256:{}", hex::encode(&root_hash)),
        signature: String::new(),
        signed_at: now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        expires_at,
        schema_version: options.schema_version.map(str::to_string),
        previous_hash: options.previous_hash.map(str::to_string),
        canonicalization: options.canonicalization.map(str::to_string),
        domain,
        signer_kid: kid,
        file_manifest: manifest,
    };

    let input = signing_input(&sig_doc)?;
    sig_doc.signature = crypto::sign_data(private_key_pem, &input)?;

    let sig_path = skill_dir.join(SIGNATURE_FILENAME);
    let json = serde_json::to_string_pretty(&sig_doc)?;
    fs::write(&sig_path, format!("{}\n", json))?;

    Ok(sig_doc)
}

fn version_tuple(version: &str) -> Option<(u32, u32)> {
    let (major, minor) = version.split_once('.')?;
    if minor.contains('.') {
        return None;
    }
    Some((major.parse().ok()?, minor.parse().ok()?))
}

fn is_legacy_version(version: &str) -> bool {
    matches!(version_tuple(version), Some(v) if v < (1, 4))
}

/// Offline skill verification using the signature's own `domain` for pinning
/// and reporting (surfaced as a `domain_unbound` warning). Prefer
/// [`verify_skill_offline_with_options`] and bind the expected domain.
///
/// If `signature_data` is `None`, loads from `.schemapin.sig` in the skill dir.
pub fn verify_skill_offline(
    skill_dir: &Path,
    discovery: &WellKnownResponse,
    signature_data: Option<&SkillSignature>,
    revocation_doc: Option<&RevocationDocument>,
    pin_store: Option<&mut KeyPinStore>,
    tool_id: Option<&str>,
) -> VerificationResult {
    verify_skill_offline_with_options(
        skill_dir,
        discovery,
        signature_data,
        revocation_doc,
        pin_store,
        &VerifyOptions {
            tool_id,
            ..VerifyOptions::default()
        },
    )
}

/// Offline skill verification.
///
/// Steps:
/// 1. Load or accept signature data; check `canonicalization`
/// 2. Bind the domain (`opts.domain` must equal the signature's domain)
/// 3. Validate discovery document, load key, compute fingerprint
/// 4. Check revocation
/// 5. TOFU pin check (read-only)
/// 6. Recompute the root hash, require `skill_hash` to match, verify the
///    signature (over the whole document for 1.4, over the root hash for
///    legacy 1.3)
/// 7. Expiration check (fail-closed unless `opts.allow_expired`)
/// 8. Pin on first use, return the result with lineage metadata
pub fn verify_skill_offline_with_options(
    skill_dir: &Path,
    discovery: &WellKnownResponse,
    signature_data: Option<&SkillSignature>,
    revocation_doc: Option<&RevocationDocument>,
    pin_store: Option<&mut KeyPinStore>,
    opts: &VerifyOptions<'_>,
) -> VerificationResult {
    // Step 1: Load signature
    let owned_sig;
    let sig = match signature_data {
        Some(s) => s,
        None => match load_signature(skill_dir) {
            Ok(s) => {
                owned_sig = s;
                &owned_sig
            }
            Err(e) => {
                return VerificationResult::failure(
                    ErrorCode::SignatureInvalid,
                    &format!("Failed to load .schemapin.sig: {}", e),
                );
            }
        },
    };

    if let Err(declared) =
        crate::canonicalize::check_canonicalization(sig.canonicalization.as_deref())
    {
        return VerificationResult::failure(
            ErrorCode::CanonicalizationUnsupported,
            &format!("Unsupported canonicalization algorithm: {}", declared),
        );
    }

    // Step 2: Domain binding
    let mut warnings = Vec::new();
    let domain = match opts.domain {
        Some(expected) => {
            let expected = match validate_domain(expected) {
                Ok(d) => d,
                Err(e) => {
                    return VerificationResult::failure(ErrorCode::DomainInvalid, &e.to_string())
                }
            };
            if sig.domain.to_ascii_lowercase() != expected {
                return VerificationResult::failure(
                    ErrorCode::DomainMismatch,
                    &format!(
                        "signature domain {:?} does not match expected domain {:?}",
                        sig.domain, expected
                    ),
                );
            }
            expected
        }
        None => match validate_domain(&sig.domain) {
            Ok(d) => {
                warnings.push("domain_unbound".to_string());
                d
            }
            Err(e) => {
                return VerificationResult::failure(
                    ErrorCode::DomainInvalid,
                    &format!("signature domain is invalid: {}", e),
                )
            }
        },
    };

    // Step 3: Validate discovery document
    if let Err(e) = validate_well_known_response(discovery) {
        return VerificationResult::failure(
            ErrorCode::DiscoveryInvalid,
            &format!("Discovery validation failed: {}", e),
        );
    }

    let fingerprint = match crypto::calculate_key_id(&discovery.public_key_pem) {
        Ok(fp) => fp,
        Err(e) => {
            return VerificationResult::failure(
                ErrorCode::KeyNotFound,
                &format!("Failed to compute key fingerprint: {}", e),
            );
        }
    };

    // Step 4: Check revocation
    if let Err(e) = check_revocation_combined(&discovery.revoked_keys, revocation_doc, &fingerprint)
    {
        let code = match &e {
            Error::Verification { code, .. } => *code,
            _ => ErrorCode::KeyRevoked,
        };
        return VerificationResult::failure(code, &e.to_string());
    }

    // Step 5: TOFU pin check (read-only until the signature verifies)
    let effective_tool_id = opts
        .tool_id
        .map(|s| s.to_string())
        .unwrap_or_else(|| sig.skill_name.clone());
    let pin_result = pin_store
        .as_ref()
        .map(|store| store.check(&effective_tool_id, &domain, &fingerprint));
    if pin_result == Some(PinningResult::Changed) {
        return VerificationResult::failure(
            ErrorCode::KeyPinMismatch,
            &format!(
                "Key for '{}@{}' has changed since last pinned (fingerprint: '{}')",
                effective_tool_id, domain, fingerprint
            ),
        );
    }

    // Step 6: Canonicalize and verify
    if version_tuple(&sig.schemapin_version).is_none() {
        return VerificationResult::failure(
            ErrorCode::SignatureInvalid,
            &format!("unsupported schemapin_version {:?}", sig.schemapin_version),
        );
    }
    let legacy = is_legacy_version(&sig.schemapin_version);
    let canonicalized = if legacy {
        canonicalize_skill_v1(skill_dir)
    } else {
        canonicalize_skill(skill_dir)
    };
    let (root_hash, _manifest) = match canonicalized {
        Ok(v) => v,
        Err(e) => {
            return VerificationResult::failure(
                ErrorCode::SchemaCanonicalizationFailed,
                &format!("Skill canonicalization failed: {}", e),
            );
        }
    };

    let verified = if legacy {
        warnings.push("legacy_signature_format".to_string());
        crypto::verify_signature(&discovery.public_key_pem, &root_hash, &sig.signature)
    } else {
        if sig.skill_hash != format!("sha256:{}", hex::encode(&root_hash)) {
            return VerificationResult::failure(
                ErrorCode::SignatureInvalid,
                "skill_hash does not match the directory contents",
            );
        }
        match signing_input(sig) {
            Ok(input) => {
                crypto::verify_signature(&discovery.public_key_pem, &input, &sig.signature)
            }
            Err(e) => {
                return VerificationResult::failure(
                    ErrorCode::SignatureInvalid,
                    &format!("malformed signature document: {}", e),
                )
            }
        }
    };
    let valid = match verified {
        Ok(v) => v,
        Err(e) => {
            return VerificationResult::failure(
                ErrorCode::SignatureInvalid,
                &format!("Signature verification error: {}", e),
            );
        }
    };
    if !valid {
        return VerificationResult::failure(
            ErrorCode::SignatureInvalid,
            "Skill signature is invalid",
        );
    }

    // Step 7: Expiration (fail-closed by default)
    let mut result = VerificationResult {
        valid: true,
        domain: Some(domain.clone()),
        developer_name: discovery.developer_name.clone(),
        key_pinning: None,
        error_code: None,
        error_message: None,
        warnings,
        expired: false,
        expires_at: None,
        schema_version: None,
        previous_hash: None,
    }
    .with_expiration_policy(sig.expires_at.as_deref(), opts.allow_expired);
    if !result.valid {
        return result;
    }

    // Step 8: Pin only now, then surface lineage metadata
    if let Some(store) = pin_store {
        let status = match pin_result {
            Some(PinningResult::FirstUse) => {
                store.pin(&effective_tool_id, &domain, &fingerprint);
                KeyPinningStatus {
                    status: "first_use".to_string(),
                    first_seen: Some(chrono::Utc::now().to_rfc3339()),
                }
            }
            _ => {
                let first_seen = store
                    .get_tool(&effective_tool_id, &domain)
                    .and_then(|t| t.pinned_keys.first())
                    .map(|pk| pk.first_seen.clone());
                KeyPinningStatus {
                    status: "pinned".to_string(),
                    first_seen,
                }
            }
        };
        result.key_pinning = Some(status);
    }
    result.with_lineage_metadata(sig.schema_version.as_deref(), sig.previous_hash.as_deref())
}

/// Errors returned by [`verify_chain`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// `current.previous_hash` is absent — the new signature doesn't claim a predecessor.
    NoPreviousHash,
    /// `current.previous_hash` is present but doesn't match `previous.skill_hash`.
    Mismatch { expected: String, got: String },
    /// One of the documents is a legacy 1.3 signature whose `skill_hash` is
    /// not covered by its signature and therefore cannot anchor a chain.
    Legacy,
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoPreviousHash => write!(f, "current signature has no previous_hash field"),
            Self::Mismatch { expected, got } => write!(
                f,
                "previous_hash mismatch: current.previous_hash = {}, previous.skill_hash = {}",
                got, expected
            ),
            Self::Legacy => write!(
                f,
                "legacy 1.3 signature documents carry an unsigned skill_hash and cannot anchor a chain"
            ),
        }
    }
}

impl std::error::Error for ChainError {}

/// Verify that `current` is the legitimate successor of `previous` via the
/// `previous_hash` lineage chain.
///
/// Returns `Ok(())` when `current.previous_hash == Some(previous.skill_hash)`.
///
/// This is a pure-metadata check — no cryptography is re-evaluated. Both
/// signatures must already be cryptographically verified separately via
/// [`verify_skill_offline`], and both must be `schemapin_version >= "1.4"`
/// documents so that `skill_hash` / `previous_hash` are covered by their
/// signatures (legacy 1.3 documents are rejected).
pub fn verify_chain(current: &SkillSignature, previous: &SkillSignature) -> Result<(), ChainError> {
    if is_legacy_version(&current.schemapin_version)
        || is_legacy_version(&previous.schemapin_version)
    {
        return Err(ChainError::Legacy);
    }
    let Some(claimed) = current.previous_hash.as_deref() else {
        return Err(ChainError::NoPreviousHash);
    };
    if claimed == previous.skill_hash {
        Ok(())
    } else {
        Err(ChainError::Mismatch {
            expected: previous.skill_hash.clone(),
            got: claimed.to_string(),
        })
    }
}

/// Verify a skill folder offline with an additional DNS TXT cross-check (v1.4).
///
/// The DNS cross-check runs before verification so that a mismatching key is
/// never pinned; a mismatch is a hard [`ErrorCode::DomainMismatch`] failure.
pub fn verify_skill_offline_with_dns(
    skill_dir: &Path,
    discovery: &WellKnownResponse,
    signature_data: Option<&SkillSignature>,
    revocation_doc: Option<&RevocationDocument>,
    pin_store: Option<&mut KeyPinStore>,
    tool_id: Option<&str>,
    dns_txt: Option<&crate::dns::DnsTxtRecord>,
) -> VerificationResult {
    verify_skill_offline_with_dns_options(
        skill_dir,
        discovery,
        signature_data,
        revocation_doc,
        pin_store,
        dns_txt,
        &VerifyOptions {
            tool_id,
            ..VerifyOptions::default()
        },
    )
}

/// [`verify_skill_offline_with_dns`] with explicit policy knobs.
pub fn verify_skill_offline_with_dns_options(
    skill_dir: &Path,
    discovery: &WellKnownResponse,
    signature_data: Option<&SkillSignature>,
    revocation_doc: Option<&RevocationDocument>,
    pin_store: Option<&mut KeyPinStore>,
    dns_txt: Option<&crate::dns::DnsTxtRecord>,
    opts: &VerifyOptions<'_>,
) -> VerificationResult {
    if let Some(txt) = dns_txt {
        match crate::dns::verify_dns_match(discovery, txt) {
            Ok(()) => {}
            Err(crate::error::Error::Verification { code, message }) => {
                return VerificationResult::failure(code, &message)
            }
            Err(e) => {
                return VerificationResult::failure(ErrorCode::DomainMismatch, &e.to_string())
            }
        }
    }
    verify_skill_offline_with_options(
        skill_dir,
        discovery,
        signature_data,
        revocation_doc,
        pin_store,
        opts,
    )
}

/// Resolve discovery via a [`SchemaResolver`], then delegate to
/// [`verify_skill_offline_with_options`]. The signature's `domain` must equal
/// `domain` (checked before any I/O) and revocation is fail-closed.
pub fn verify_skill_with_resolver(
    skill_dir: &Path,
    domain: &str,
    resolver: &dyn SchemaResolver,
    pin_store: Option<&mut KeyPinStore>,
    tool_id: Option<&str>,
) -> VerificationResult {
    verify_skill_with_resolver_opts(
        skill_dir,
        domain,
        resolver,
        pin_store,
        tool_id,
        ResolverOptions::default(),
    )
}

/// [`verify_skill_with_resolver`] with explicit policy knobs.
pub fn verify_skill_with_resolver_opts(
    skill_dir: &Path,
    domain: &str,
    resolver: &dyn SchemaResolver,
    pin_store: Option<&mut KeyPinStore>,
    tool_id: Option<&str>,
    ropts: ResolverOptions,
) -> VerificationResult {
    let domain = match validate_domain(domain) {
        Ok(d) => d,
        Err(e) => return VerificationResult::failure(ErrorCode::DomainInvalid, &e.to_string()),
    };

    let sig = match load_signature(skill_dir) {
        Ok(s) => s,
        Err(e) => {
            return VerificationResult::failure(
                ErrorCode::SignatureInvalid,
                &format!("Failed to load .schemapin.sig: {}", e),
            );
        }
    };
    if sig.domain.to_ascii_lowercase() != domain {
        return VerificationResult::failure(
            ErrorCode::DomainMismatch,
            &format!(
                "signature domain {:?} does not match expected domain {:?}",
                sig.domain, domain
            ),
        );
    }

    let discovery = match resolver.resolve_discovery(&domain) {
        Ok(doc) => doc,
        Err(e) => {
            return VerificationResult::failure(
                ErrorCode::DiscoveryFetchFailed,
                &format!("Failed to resolve discovery document: {}", e),
            );
        }
    };

    let revocation = match resolver.resolve_revocation(&domain, &discovery) {
        Ok(doc) => doc,
        Err(e) => {
            if !ropts.allow_unreachable_revocation {
                return VerificationResult::failure(
                    ErrorCode::DiscoveryFetchFailed,
                    &format!("Revocation document unreachable (fail-closed): {}", e),
                );
            }
            None
        }
    };

    verify_skill_offline_with_options(
        skill_dir,
        &discovery,
        Some(&sig),
        revocation.as_ref(),
        pin_store,
        &VerifyOptions {
            domain: Some(&domain),
            tool_id,
            allow_expired: ropts.allow_expired,
        },
    )
}

/// Compare two file manifests and report differences.
///
/// Only meaningful for `schemapin_version >= "1.4"` documents, whose
/// `file_manifest` is covered by the signature; for legacy 1.3 documents the
/// manifest is unsigned and this is a diagnostic aid only.
pub fn detect_tampered_files(
    current: &BTreeMap<String, String>,
    signed: &BTreeMap<String, String>,
) -> TamperedFiles {
    let mut result = TamperedFiles::default();

    for (path, hash) in current {
        match signed.get(path) {
            Some(signed_hash) if signed_hash != hash => {
                result.modified.push(path.clone());
            }
            None => {
                result.added.push(path.clone());
            }
            _ => {}
        }
    }

    for path in signed.keys() {
        if !current.contains_key(path) {
            result.removed.push(path.clone());
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_key_pair;
    use crate::discovery::build_well_known_response;
    use crate::pinning::KeyPinStore;
    use crate::resolver::TrustBundleResolver;
    use crate::revocation::{add_revoked_key, build_revocation_document};
    use crate::types::bundle::{BundledDiscovery, SchemaPinTrustBundle};
    use crate::types::revocation::RevocationReason;
    use tempfile::tempdir;

    /// Write files into a temp directory.
    fn make_skill_dir(dir: &Path, files: &[(&str, &[u8])]) {
        for (rel_path, contents) in files {
            let full = dir.join(rel_path);
            if let Some(parent) = full.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&full, contents).unwrap();
        }
    }

    // ── canonicalize tests ──────────────────────────────────────────

    #[test]
    fn test_canonicalize_sorted_deterministic() {
        let dir = tempdir().unwrap();
        make_skill_dir(dir.path(), &[("b.txt", b"BBB"), ("a.txt", b"AAA")]);
        let (h1, m1) = canonicalize_skill(dir.path()).unwrap();
        let (h2, m2) = canonicalize_skill(dir.path()).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(m1, m2);
    }

    #[test]
    fn test_canonicalize_skip_sig_file() {
        let dir = tempdir().unwrap();
        make_skill_dir(
            dir.path(),
            &[
                ("file.txt", b"data"),
                (".schemapin.sig", b"should be skipped"),
            ],
        );
        let (_, manifest) = canonicalize_skill(dir.path()).unwrap();
        assert!(!manifest.contains_key(".schemapin.sig"));
        assert_eq!(manifest.len(), 1);
    }

    #[test]
    fn test_canonicalize_nested_dirs() {
        let dir = tempdir().unwrap();
        make_skill_dir(
            dir.path(),
            &[
                ("top.txt", b"top"),
                ("sub/inner.txt", b"inner"),
                ("sub/deep/leaf.txt", b"leaf"),
            ],
        );
        let (_, manifest) = canonicalize_skill(dir.path()).unwrap();
        assert_eq!(manifest.len(), 3);
        assert!(manifest.contains_key("sub/inner.txt"));
        assert!(manifest.contains_key("sub/deep/leaf.txt"));
    }

    #[test]
    fn test_canonicalize_forward_slashes() {
        let dir = tempdir().unwrap();
        make_skill_dir(dir.path(), &[("a/b/c.txt", b"data")]);
        let (_, manifest) = canonicalize_skill(dir.path()).unwrap();
        for key in manifest.keys() {
            assert!(!key.contains('\\'), "backslash in key: {}", key);
        }
    }

    #[test]
    fn test_canonicalize_empty_dir() {
        let dir = tempdir().unwrap();
        let result = canonicalize_skill(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_canonicalize_binary_files() {
        let dir = tempdir().unwrap();
        let binary: Vec<u8> = (0..=255).collect();
        make_skill_dir(dir.path(), &[("binary.bin", &binary)]);
        let (hash, manifest) = canonicalize_skill(dir.path()).unwrap();
        assert_eq!(manifest.len(), 1);
        assert!(!hash.is_empty());
        assert!(manifest["binary.bin"].starts_with("sha256:"));
    }

    // ── parse_skill_name tests ──────────────────────────────────────

    #[test]
    fn test_parse_skill_name_frontmatter() {
        let dir = tempdir().unwrap();
        make_skill_dir(
            dir.path(),
            &[(
                "SKILL.md",
                b"---\nname: my-cool-skill\ndescription: stuff\n---\n# Hello",
            )],
        );
        assert_eq!(parse_skill_name(dir.path()), "my-cool-skill");
    }

    #[test]
    fn test_parse_skill_name_quoted() {
        let dir = tempdir().unwrap();
        make_skill_dir(
            dir.path(),
            &[("SKILL.md", b"---\nname: 'quoted-skill'\n---\nbody")],
        );
        assert_eq!(parse_skill_name(dir.path()), "quoted-skill");

        let dir2 = tempdir().unwrap();
        make_skill_dir(
            dir2.path(),
            &[("SKILL.md", b"---\nname: \"double-quoted\"\n---\nbody")],
        );
        assert_eq!(parse_skill_name(dir2.path()), "double-quoted");
    }

    #[test]
    fn test_parse_skill_name_fallback() {
        let dir = tempdir().unwrap();
        // No SKILL.md → falls back to dirname
        let name = parse_skill_name(dir.path());
        // tempdir names vary, but should not be empty
        assert!(!name.is_empty());
    }

    // ── sign / roundtrip tests ──────────────────────────────────────

    #[test]
    fn test_sign_creates_file() {
        let dir = tempdir().unwrap();
        make_skill_dir(dir.path(), &[("SKILL.md", b"---\nname: test-skill\n---\n")]);
        let kp = generate_key_pair().unwrap();
        sign_skill(dir.path(), &kp.private_key_pem, "example.com", None, None).unwrap();
        assert!(dir.path().join(".schemapin.sig").exists());
    }

    #[test]
    fn test_sign_roundtrip() {
        let dir = tempdir().unwrap();
        make_skill_dir(
            dir.path(),
            &[
                ("SKILL.md", b"---\nname: roundtrip\n---\n"),
                ("lib.rs", b"fn main() {}"),
            ],
        );
        let kp = generate_key_pair().unwrap();
        let sig = sign_skill(dir.path(), &kp.private_key_pem, "example.com", None, None).unwrap();

        let discovery = build_well_known_response(&kp.public_key_pem, Some("Dev"), vec![], "1.3");
        let result = verify_skill_offline(dir.path(), &discovery, Some(&sig), None, None, None);
        assert!(result.valid, "Expected valid, got: {:?}", result);
    }

    #[test]
    fn test_wrong_key_fails() {
        let dir = tempdir().unwrap();
        make_skill_dir(dir.path(), &[("file.txt", b"content")]);
        let kp1 = generate_key_pair().unwrap();
        let kp2 = generate_key_pair().unwrap();
        let sig = sign_skill(
            dir.path(),
            &kp1.private_key_pem,
            "example.com",
            None,
            Some("t"),
        )
        .unwrap();

        let discovery =
            build_well_known_response(&kp2.public_key_pem, Some("Other"), vec![], "1.3");
        let result = verify_skill_offline(dir.path(), &discovery, Some(&sig), None, None, None);
        assert!(!result.valid);
        assert_eq!(result.error_code, Some(ErrorCode::SignatureInvalid));
    }

    #[test]
    fn test_tampered_file_fails() {
        let dir = tempdir().unwrap();
        make_skill_dir(dir.path(), &[("file.txt", b"original")]);
        let kp = generate_key_pair().unwrap();
        let sig = sign_skill(
            dir.path(),
            &kp.private_key_pem,
            "example.com",
            None,
            Some("t"),
        )
        .unwrap();

        // Tamper
        fs::write(dir.path().join("file.txt"), b"tampered").unwrap();

        let discovery = build_well_known_response(&kp.public_key_pem, Some("Dev"), vec![], "1.3");
        let result = verify_skill_offline(dir.path(), &discovery, Some(&sig), None, None, None);
        assert!(!result.valid);
        assert_eq!(result.error_code, Some(ErrorCode::SignatureInvalid));
    }

    #[test]
    fn test_added_file_fails() {
        let dir = tempdir().unwrap();
        make_skill_dir(dir.path(), &[("file.txt", b"orig")]);
        let kp = generate_key_pair().unwrap();
        let sig = sign_skill(
            dir.path(),
            &kp.private_key_pem,
            "example.com",
            None,
            Some("t"),
        )
        .unwrap();

        // Add a file
        fs::write(dir.path().join("extra.txt"), b"extra").unwrap();

        let discovery = build_well_known_response(&kp.public_key_pem, Some("Dev"), vec![], "1.3");
        let result = verify_skill_offline(dir.path(), &discovery, Some(&sig), None, None, None);
        assert!(!result.valid);
    }

    #[test]
    fn test_removed_file_fails() {
        let dir = tempdir().unwrap();
        make_skill_dir(dir.path(), &[("a.txt", b"aaa"), ("b.txt", b"bbb")]);
        let kp = generate_key_pair().unwrap();
        let sig = sign_skill(
            dir.path(),
            &kp.private_key_pem,
            "example.com",
            None,
            Some("t"),
        )
        .unwrap();

        // Remove a file
        fs::remove_file(dir.path().join("b.txt")).unwrap();

        let discovery = build_well_known_response(&kp.public_key_pem, Some("Dev"), vec![], "1.3");
        let result = verify_skill_offline(dir.path(), &discovery, Some(&sig), None, None, None);
        assert!(!result.valid);
    }

    // ── verify_skill_offline edge cases ─────────────────────────────

    #[test]
    fn test_verify_offline_happy_path() {
        let dir = tempdir().unwrap();
        make_skill_dir(
            dir.path(),
            &[
                ("SKILL.md", b"---\nname: happy\n---\n"),
                ("code.py", b"print('hello')"),
            ],
        );
        let kp = generate_key_pair().unwrap();
        sign_skill(dir.path(), &kp.private_key_pem, "example.com", None, None).unwrap();

        let discovery = build_well_known_response(&kp.public_key_pem, Some("Dev"), vec![], "1.3");
        let mut pin_store = KeyPinStore::new();
        let result = verify_skill_offline(
            dir.path(),
            &discovery,
            None,
            None,
            Some(&mut pin_store),
            Some("happy"),
        );
        assert!(result.valid, "Expected valid, got: {:?}", result);
        assert_eq!(result.domain, Some("example.com".to_string()));
        let pin = result.key_pinning.unwrap();
        assert_eq!(pin.status, "first_use");
    }

    #[test]
    fn test_verify_offline_revoked_key() {
        let dir = tempdir().unwrap();
        make_skill_dir(dir.path(), &[("f.txt", b"data")]);
        let kp = generate_key_pair().unwrap();
        sign_skill(
            dir.path(),
            &kp.private_key_pem,
            "example.com",
            None,
            Some("t"),
        )
        .unwrap();

        let fp = crypto::calculate_key_id(&kp.public_key_pem).unwrap();
        let mut rev_doc = build_revocation_document("example.com");
        add_revoked_key(&mut rev_doc, &fp, RevocationReason::KeyCompromise);

        let discovery = build_well_known_response(&kp.public_key_pem, Some("Dev"), vec![], "1.3");
        let result = verify_skill_offline(dir.path(), &discovery, None, Some(&rev_doc), None, None);
        assert!(!result.valid);
        assert_eq!(result.error_code, Some(ErrorCode::KeyRevoked));
    }

    #[test]
    fn test_verify_offline_pin_mismatch() {
        let dir = tempdir().unwrap();
        make_skill_dir(dir.path(), &[("f.txt", b"data")]);
        let kp1 = generate_key_pair().unwrap();
        let kp2 = generate_key_pair().unwrap();

        // Sign with key1 and verify once to pin
        sign_skill(
            dir.path(),
            &kp1.private_key_pem,
            "example.com",
            None,
            Some("tool1"),
        )
        .unwrap();
        let disc1 = build_well_known_response(&kp1.public_key_pem, Some("Dev"), vec![], "1.3");
        let mut pin_store = KeyPinStore::new();
        let r1 = verify_skill_offline(
            dir.path(),
            &disc1,
            None,
            None,
            Some(&mut pin_store),
            Some("tool1"),
        );
        assert!(r1.valid);

        // Now sign with key2 — pinning should reject
        sign_skill(
            dir.path(),
            &kp2.private_key_pem,
            "example.com",
            None,
            Some("tool1"),
        )
        .unwrap();
        let disc2 = build_well_known_response(&kp2.public_key_pem, Some("Dev2"), vec![], "1.3");
        let result = verify_skill_offline(
            dir.path(),
            &disc2,
            None,
            None,
            Some(&mut pin_store),
            Some("tool1"),
        );
        assert!(!result.valid);
        assert_eq!(result.error_code, Some(ErrorCode::KeyPinMismatch));
    }

    #[test]
    fn test_verify_offline_invalid_discovery() {
        let dir = tempdir().unwrap();
        make_skill_dir(dir.path(), &[("f.txt", b"data")]);
        let kp = generate_key_pair().unwrap();
        sign_skill(
            dir.path(),
            &kp.private_key_pem,
            "example.com",
            None,
            Some("t"),
        )
        .unwrap();

        let mut discovery =
            build_well_known_response(&kp.public_key_pem, Some("Dev"), vec![], "1.3");
        discovery.public_key_pem = String::new(); // invalid

        let result = verify_skill_offline(dir.path(), &discovery, None, None, None, None);
        assert!(!result.valid);
        assert_eq!(result.error_code, Some(ErrorCode::DiscoveryInvalid));
    }

    #[test]
    fn test_verify_offline_missing_sig() {
        let dir = tempdir().unwrap();
        make_skill_dir(dir.path(), &[("f.txt", b"data")]);
        let kp = generate_key_pair().unwrap();
        let discovery = build_well_known_response(&kp.public_key_pem, Some("Dev"), vec![], "1.3");
        // No .schemapin.sig written
        let result = verify_skill_offline(dir.path(), &discovery, None, None, None, None);
        assert!(!result.valid);
        assert_eq!(result.error_code, Some(ErrorCode::SignatureInvalid));
    }

    // ── detect_tampered_files ───────────────────────────────────────

    #[test]
    fn test_detect_tampered_files() {
        let mut signed = BTreeMap::new();
        signed.insert("a.txt".to_string(), "sha256:aaa".to_string());
        signed.insert("b.txt".to_string(), "sha256:bbb".to_string());
        signed.insert("c.txt".to_string(), "sha256:ccc".to_string());

        let mut current = BTreeMap::new();
        current.insert("a.txt".to_string(), "sha256:aaa".to_string()); // unchanged
        current.insert("b.txt".to_string(), "sha256:XXX".to_string()); // modified
        current.insert("d.txt".to_string(), "sha256:ddd".to_string()); // added

        let diff = detect_tampered_files(&current, &signed);
        assert_eq!(diff.modified, vec!["b.txt"]);
        assert_eq!(diff.added, vec!["d.txt"]);
        assert_eq!(diff.removed, vec!["c.txt"]);
    }

    // ── verify_skill_with_resolver ──────────────────────────────────

    #[test]
    fn test_verify_with_resolver() {
        let dir = tempdir().unwrap();
        make_skill_dir(
            dir.path(),
            &[
                ("SKILL.md", b"---\nname: resolver-test\n---\n"),
                ("main.py", b"print(1)"),
            ],
        );
        let kp = generate_key_pair().unwrap();
        sign_skill(dir.path(), &kp.private_key_pem, "example.com", None, None).unwrap();

        let discovery = build_well_known_response(&kp.public_key_pem, Some("Dev"), vec![], "1.3");
        let bundle = SchemaPinTrustBundle {
            schemapin_bundle_version: "1.3".to_string(),
            created_at: "2026-02-14T00:00:00Z".to_string(),
            documents: vec![BundledDiscovery {
                domain: "example.com".to_string(),
                well_known: discovery,
            }],
            revocations: vec![],
            ..Default::default()
        };
        let resolver = TrustBundleResolver::new(&bundle);
        let mut pin_store = KeyPinStore::new();

        let result = verify_skill_with_resolver(
            dir.path(),
            "example.com",
            &resolver,
            Some(&mut pin_store),
            Some("resolver-test"),
        );
        assert!(result.valid, "Expected valid, got: {:?}", result);
        assert_eq!(result.domain, Some("example.com".to_string()));
    }

    // ── v1.4: signature expiration tests ────────────────────────────

    #[test]
    fn test_sign_with_ttl_writes_expires_at() {
        let dir = tempdir().unwrap();
        make_skill_dir(dir.path(), &[("SKILL.md", b"---\nname: ttl\n---\n")]);
        let kp = generate_key_pair().unwrap();
        let opts = SignOptions::new().with_expires_in(chrono::Duration::days(30));
        let sig =
            sign_skill_with_options(dir.path(), &kp.private_key_pem, "example.com", opts).unwrap();
        assert!(sig.expires_at.is_some(), "expires_at should be set");
        assert_eq!(sig.schemapin_version, "1.4");
        // Round-trip through disk to ensure JSON contains the field.
        let on_disk = load_signature(dir.path()).unwrap();
        assert_eq!(on_disk.expires_at, sig.expires_at);
    }

    #[test]
    fn test_sign_without_ttl_omits_expires_at() {
        let dir = tempdir().unwrap();
        make_skill_dir(dir.path(), &[("SKILL.md", b"---\nname: no-ttl\n---\n")]);
        let kp = generate_key_pair().unwrap();
        let sig = sign_skill(dir.path(), &kp.private_key_pem, "example.com", None, None).unwrap();
        assert!(sig.expires_at.is_none());
        assert_eq!(sig.schemapin_version, "1.4");
        let raw = fs::read_to_string(dir.path().join(".schemapin.sig")).unwrap();
        assert!(!raw.contains("expires_at"), "JSON should omit expires_at");
    }

    #[test]
    fn test_verify_with_future_ttl_passes_no_warnings() {
        let dir = tempdir().unwrap();
        make_skill_dir(dir.path(), &[("SKILL.md", b"---\nname: future\n---\n")]);
        let kp = generate_key_pair().unwrap();
        let opts = SignOptions::new().with_expires_in(chrono::Duration::days(30));
        sign_skill_with_options(dir.path(), &kp.private_key_pem, "example.com", opts).unwrap();

        let discovery = build_well_known_response(&kp.public_key_pem, Some("Dev"), vec![], "1.3");
        let result = verify_skill_offline(dir.path(), &discovery, None, None, None, Some("future"));
        assert!(result.valid);
        assert!(!result.expired);
        assert!(result.expires_at.is_some());
        assert!(
            !result.warnings.iter().any(|w| w == "signature_expired"),
            "no expiration warning expected"
        );
    }

    #[test]
    fn test_verify_with_past_ttl_fails_closed() {
        let dir = tempdir().unwrap();
        make_skill_dir(dir.path(), &[("SKILL.md", b"---\nname: past\n---\n")]);
        let kp = generate_key_pair().unwrap();
        let opts = SignOptions::new().with_expires_in(-chrono::Duration::days(1));
        sign_skill_with_options(dir.path(), &kp.private_key_pem, "example.com", opts).unwrap();

        let discovery = build_well_known_response(&kp.public_key_pem, Some("Dev"), vec![], "1.3");
        let result = verify_skill_offline(dir.path(), &discovery, None, None, None, Some("past"));
        assert!(!result.valid, "expired signatures fail closed by default");
        assert_eq!(result.error_code, Some(ErrorCode::SignatureExpired));
        assert!(result.expired);

        let degraded = verify_skill_offline_with_options(
            dir.path(),
            &discovery,
            None,
            None,
            None,
            &VerifyOptions {
                tool_id: Some("past"),
                allow_expired: true,
                ..VerifyOptions::default()
            },
        );
        assert!(degraded.valid, "allow_expired degrades instead of failing");
        assert!(degraded.expired);
        assert!(degraded.warnings.iter().any(|w| w == "signature_expired"));
    }

    #[test]
    fn test_expires_at_is_covered_by_signature() {
        let dir = tempdir().unwrap();
        make_skill_dir(dir.path(), &[("SKILL.md", b"---\nname: strip\n---\n")]);
        let kp = generate_key_pair().unwrap();
        let opts = SignOptions::new().with_expires_in(-chrono::Duration::days(1));
        let mut sig =
            sign_skill_with_options(dir.path(), &kp.private_key_pem, "example.com", opts).unwrap();
        let discovery = build_well_known_response(&kp.public_key_pem, Some("Dev"), vec![], "1.4");

        sig.expires_at = None;
        fs::write(
            dir.path().join(".schemapin.sig"),
            serde_json::to_string(&sig).unwrap(),
        )
        .unwrap();
        let r = verify_skill_offline(dir.path(), &discovery, None, None, None, None);
        assert!(!r.valid);
        assert_eq!(r.error_code, Some(ErrorCode::SignatureInvalid));

        sig.schemapin_version = "1.3".to_string();
        fs::write(
            dir.path().join(".schemapin.sig"),
            serde_json::to_string(&sig).unwrap(),
        )
        .unwrap();
        assert!(!verify_skill_offline(dir.path(), &discovery, None, None, None, None).valid);
    }

    // ── v1.4: DNS TXT cross-verification tests ─────────────────────

    #[test]
    fn test_verify_with_dns_match_passes() {
        let dir = tempdir().unwrap();
        make_skill_dir(dir.path(), &[("SKILL.md", b"---\nname: dnsok\n---\n")]);
        let kp = generate_key_pair().unwrap();
        sign_skill(dir.path(), &kp.private_key_pem, "example.com", None, None).unwrap();

        let discovery = build_well_known_response(&kp.public_key_pem, Some("Dev"), vec![], "1.4");
        let fp = crypto::calculate_key_id(&kp.public_key_pem)
            .unwrap()
            .to_ascii_lowercase();
        let txt = crate::dns::DnsTxtRecord {
            version: "schemapin1".to_string(),
            kid: None,
            fingerprint: fp,
        };
        let result = verify_skill_offline_with_dns(
            dir.path(),
            &discovery,
            None,
            None,
            None,
            Some("dnsok"),
            Some(&txt),
        );
        assert!(result.valid, "expected valid, got: {:?}", result);
    }

    #[test]
    fn test_verify_with_dns_mismatch_fails() {
        let dir = tempdir().unwrap();
        make_skill_dir(dir.path(), &[("SKILL.md", b"---\nname: dnsbad\n---\n")]);
        let kp = generate_key_pair().unwrap();
        sign_skill(dir.path(), &kp.private_key_pem, "example.com", None, None).unwrap();

        let discovery = build_well_known_response(&kp.public_key_pem, Some("Dev"), vec![], "1.4");
        let txt = crate::dns::DnsTxtRecord {
            version: "schemapin1".to_string(),
            kid: None,
            fingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
        };
        let result = verify_skill_offline_with_dns(
            dir.path(),
            &discovery,
            None,
            None,
            None,
            Some("dnsbad"),
            Some(&txt),
        );
        assert!(!result.valid);
        assert_eq!(result.error_code, Some(ErrorCode::DomainMismatch));
    }

    #[test]
    fn test_verify_without_dns_txt_unchanged() {
        let dir = tempdir().unwrap();
        make_skill_dir(dir.path(), &[("SKILL.md", b"---\nname: nodns\n---\n")]);
        let kp = generate_key_pair().unwrap();
        sign_skill(dir.path(), &kp.private_key_pem, "example.com", None, None).unwrap();

        let discovery = build_well_known_response(&kp.public_key_pem, Some("Dev"), vec![], "1.4");
        // dns_txt = None should behave exactly like verify_skill_offline.
        let result = verify_skill_offline_with_dns(
            dir.path(),
            &discovery,
            None,
            None,
            None,
            Some("nodns"),
            None,
        );
        assert!(result.valid);
    }

    #[test]
    fn test_unparseable_expires_at_fails_closed() {
        for bad in [
            "not-a-timestamp",
            "2020-01-01",
            "2020-01-01T00:00:00",
            "2020-01-01 00:00:00Z",
        ] {
            let r = VerificationResult::failure(ErrorCode::SignatureInvalid, "x");
            let mut r = r;
            r.valid = true;
            r.error_code = None;
            let strict = r.clone().with_expiration_policy(Some(bad), false);
            assert!(!strict.valid, "{} must fail closed", bad);
            assert_eq!(strict.error_code, Some(ErrorCode::SignatureExpired));
            let lenient = r.with_expiration_policy(Some(bad), true);
            assert!(lenient.valid);
            assert!(lenient
                .warnings
                .iter()
                .any(|w| w == "signature_expires_at_unparseable"));
        }
    }

    // ── v1.4 alpha.2: schema_version + previous_hash lineage tests ──

    #[test]
    fn test_sign_with_schema_version_writes_field() {
        let dir = tempdir().unwrap();
        make_skill_dir(dir.path(), &[("SKILL.md", b"---\nname: ver\n---\n")]);
        let kp = generate_key_pair().unwrap();
        let opts = SignOptions::new().with_schema_version("2.1.0");
        let sig =
            sign_skill_with_options(dir.path(), &kp.private_key_pem, "example.com", opts).unwrap();
        assert_eq!(sig.schema_version.as_deref(), Some("2.1.0"));
        assert_eq!(sig.schemapin_version, "1.4");
        let on_disk = load_signature(dir.path()).unwrap();
        assert_eq!(on_disk.schema_version.as_deref(), Some("2.1.0"));
    }

    #[test]
    fn test_sign_without_schema_version_omits_field() {
        let dir = tempdir().unwrap();
        make_skill_dir(dir.path(), &[("SKILL.md", b"---\nname: noversion\n---\n")]);
        let kp = generate_key_pair().unwrap();
        let sig = sign_skill(dir.path(), &kp.private_key_pem, "example.com", None, None).unwrap();
        assert!(sig.schema_version.is_none());
        let raw = fs::read_to_string(dir.path().join(".schemapin.sig")).unwrap();
        assert!(
            !raw.contains("schema_version"),
            "JSON should omit schema_version"
        );
        assert!(
            !raw.contains("previous_hash"),
            "JSON should omit previous_hash"
        );
    }

    #[test]
    fn test_sign_with_previous_hash_writes_field() {
        let dir = tempdir().unwrap();
        make_skill_dir(dir.path(), &[("SKILL.md", b"---\nname: chained\n---\n")]);
        let kp = generate_key_pair().unwrap();
        let opts = SignOptions::new().with_previous_hash("sha256:abcdef");
        let sig =
            sign_skill_with_options(dir.path(), &kp.private_key_pem, "example.com", opts).unwrap();
        assert_eq!(sig.previous_hash.as_deref(), Some("sha256:abcdef"));
        assert_eq!(sig.schemapin_version, "1.4");
    }

    #[test]
    fn test_verify_chain_matches() {
        let dir1 = tempdir().unwrap();
        make_skill_dir(dir1.path(), &[("SKILL.md", b"---\nname: v1\n---\n")]);
        let kp = generate_key_pair().unwrap();
        let v1 = sign_skill(dir1.path(), &kp.private_key_pem, "example.com", None, None).unwrap();

        let dir2 = tempdir().unwrap();
        make_skill_dir(dir2.path(), &[("SKILL.md", b"---\nname: v2\n---\n")]);
        let opts = SignOptions::new().with_previous_hash(&v1.skill_hash);
        let v2 =
            sign_skill_with_options(dir2.path(), &kp.private_key_pem, "example.com", opts).unwrap();

        verify_chain(&v2, &v1).unwrap();
    }

    #[test]
    fn test_verify_chain_no_previous_hash_errors() {
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        make_skill_dir(dir1.path(), &[("SKILL.md", b"---\nname: v1\n---\n")]);
        make_skill_dir(dir2.path(), &[("SKILL.md", b"---\nname: v2\n---\n")]);
        let kp = generate_key_pair().unwrap();
        let v1 = sign_skill(dir1.path(), &kp.private_key_pem, "example.com", None, None).unwrap();
        let v2 = sign_skill(dir2.path(), &kp.private_key_pem, "example.com", None, None).unwrap();

        // v2 has no previous_hash → chain check rejects
        assert_eq!(verify_chain(&v2, &v1), Err(ChainError::NoPreviousHash));
    }

    #[test]
    fn test_verify_chain_mismatch_errors() {
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        make_skill_dir(dir1.path(), &[("SKILL.md", b"---\nname: v1\n---\n")]);
        make_skill_dir(dir2.path(), &[("SKILL.md", b"---\nname: v2\n---\n")]);
        let kp = generate_key_pair().unwrap();
        let v1 = sign_skill(dir1.path(), &kp.private_key_pem, "example.com", None, None).unwrap();
        let opts = SignOptions::new().with_previous_hash("sha256:not-the-real-prior-hash");
        let v2 =
            sign_skill_with_options(dir2.path(), &kp.private_key_pem, "example.com", opts).unwrap();

        match verify_chain(&v2, &v1).unwrap_err() {
            ChainError::Mismatch { expected, got } => {
                assert_eq!(expected, v1.skill_hash);
                assert_eq!(got, "sha256:not-the-real-prior-hash");
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_verify_skill_offline_surfaces_lineage_metadata() {
        let dir = tempdir().unwrap();
        make_skill_dir(dir.path(), &[("SKILL.md", b"---\nname: surfaced\n---\n")]);
        let kp = generate_key_pair().unwrap();
        let opts = SignOptions::new()
            .with_schema_version("3.2.1")
            .with_previous_hash("sha256:deadbeef");
        sign_skill_with_options(dir.path(), &kp.private_key_pem, "example.com", opts).unwrap();

        let discovery = build_well_known_response(&kp.public_key_pem, Some("Dev"), vec![], "1.4");
        let result =
            verify_skill_offline(dir.path(), &discovery, None, None, None, Some("surfaced"));
        assert!(result.valid);
        assert_eq!(result.schema_version.as_deref(), Some("3.2.1"));
        assert_eq!(result.previous_hash.as_deref(), Some("sha256:deadbeef"));
    }

    #[test]
    fn test_combined_v1_4_fields_all_round_trip() {
        let dir = tempdir().unwrap();
        make_skill_dir(dir.path(), &[("SKILL.md", b"---\nname: combo\n---\n")]);
        let kp = generate_key_pair().unwrap();
        let opts = SignOptions::new()
            .with_expires_in(chrono::Duration::days(180))
            .with_schema_version("1.0.0")
            .with_previous_hash("sha256:cafebabe");
        let sig =
            sign_skill_with_options(dir.path(), &kp.private_key_pem, "example.com", opts).unwrap();
        assert_eq!(sig.schemapin_version, "1.4");
        assert!(sig.expires_at.is_some());
        assert_eq!(sig.schema_version.as_deref(), Some("1.0.0"));
        assert_eq!(sig.previous_hash.as_deref(), Some("sha256:cafebabe"));

        let on_disk = load_signature(dir.path()).unwrap();
        assert_eq!(on_disk.expires_at, sig.expires_at);
        assert_eq!(on_disk.schema_version, sig.schema_version);
        assert_eq!(on_disk.previous_hash, sig.previous_hash);
    }

    // ── signed signature document, domain binding, hashing v2 ──────

    fn sign_legacy_v13(dir: &Path, private_key_pem: &str, domain: &str) -> SkillSignature {
        let (root_hash, manifest) = canonicalize_skill_v1(dir).unwrap();
        let secret = p256::SecretKey::from_pkcs8_pem(private_key_pem).unwrap();
        let pem = secret
            .public_key()
            .to_public_key_pem(p256::pkcs8::LineEnding::LF)
            .unwrap();
        let sig = SkillSignature {
            schemapin_version: "1.3".to_string(),
            skill_name: "legacy".to_string(),
            skill_hash: format!("sha256:{}", hex::encode(&root_hash)),
            signature: crypto::sign_data(private_key_pem, &root_hash).unwrap(),
            signed_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: None,
            schema_version: None,
            previous_hash: None,
            canonicalization: None,
            domain: domain.to_string(),
            signer_kid: crypto::calculate_key_id(&pem).unwrap(),
            file_manifest: manifest,
        };
        fs::write(
            dir.join(".schemapin.sig"),
            serde_json::to_string(&sig).unwrap(),
        )
        .unwrap();
        sig
    }

    fn write_sig(dir: &Path, sig: &SkillSignature) {
        fs::write(
            dir.join(".schemapin.sig"),
            serde_json::to_string(sig).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn test_metadata_tamper_invalidates() {
        let kp = generate_key_pair().unwrap();
        let discovery = build_well_known_response(&kp.public_key_pem, Some("Dev"), vec![], "1.4");
        type Mutation = Box<dyn Fn(&mut SkillSignature)>;
        let mutations: Vec<Mutation> = vec![
            Box::new(|s| s.schema_version = Some("9.9.9".to_string())),
            Box::new(|s| s.previous_hash = Some(format!("sha256:{}", "ab".repeat(32)))),
            Box::new(|s| s.skill_name = "payments-tool".to_string()),
            Box::new(|s| s.domain = "good.example.com".to_string()),
            Box::new(|s| s.signer_kid = format!("sha256:{}", "00".repeat(32))),
            Box::new(|s| s.signed_at = "2030-01-01T00:00:00Z".to_string()),
            Box::new(|s| s.canonicalization = Some("schemapin-v1".to_string())),
            Box::new(|s| {
                s.file_manifest.insert(
                    "extra.txt".to_string(),
                    format!("sha256:{}", "00".repeat(32)),
                );
            }),
        ];
        for (i, mutate) in mutations.iter().enumerate() {
            let dir = tempdir().unwrap();
            make_skill_dir(dir.path(), &[("SKILL.md", b"---\nname: s\n---\n")]);
            let opts = SignOptions::new().with_schema_version("1.0.0");
            let mut sig =
                sign_skill_with_options(dir.path(), &kp.private_key_pem, "example.com", opts)
                    .unwrap();
            mutate(&mut sig);
            write_sig(dir.path(), &sig);
            let r = verify_skill_offline(dir.path(), &discovery, None, None, None, None);
            assert!(!r.valid, "mutation {} must invalidate the signature", i);
        }
    }

    #[test]
    fn test_skill_hash_is_hex_root_and_verified() {
        let kp = generate_key_pair().unwrap();
        let dir = tempdir().unwrap();
        make_skill_dir(dir.path(), &[("SKILL.md", b"# hi")]);
        let sig = sign_skill(dir.path(), &kp.private_key_pem, "example.com", None, None).unwrap();
        let (root, _) = canonicalize_skill(dir.path()).unwrap();
        assert_eq!(sig.skill_hash, format!("sha256:{}", hex::encode(&root)));

        let other = tempdir().unwrap();
        make_skill_dir(other.path(), &[("SKILL.md", b"# other")]);
        let other_sig =
            sign_skill(other.path(), &kp.private_key_pem, "example.com", None, None).unwrap();
        write_sig(dir.path(), &other_sig);
        let discovery = build_well_known_response(&kp.public_key_pem, Some("Dev"), vec![], "1.4");
        let r = verify_skill_offline(dir.path(), &discovery, None, None, None, None);
        assert!(!r.valid);
        assert!(r.error_message.unwrap().contains("skill_hash"));
    }

    #[test]
    fn test_legacy_v13_document_verifies_with_warning() {
        let kp = generate_key_pair().unwrap();
        let dir = tempdir().unwrap();
        make_skill_dir(dir.path(), &[("SKILL.md", b"# hi"), ("sub/x.txt", b"x")]);
        let mut sig = sign_legacy_v13(dir.path(), &kp.private_key_pem, "example.com");
        let discovery = build_well_known_response(&kp.public_key_pem, Some("Dev"), vec![], "1.4");
        let r = verify_skill_offline_with_options(
            dir.path(),
            &discovery,
            None,
            None,
            None,
            &VerifyOptions {
                domain: Some("example.com"),
                ..VerifyOptions::default()
            },
        );
        assert!(r.valid, "{:?}", r);
        assert!(r.warnings.iter().any(|w| w == "legacy_signature_format"));

        sig.schemapin_version = "1.4".to_string();
        write_sig(dir.path(), &sig);
        assert!(!verify_skill_offline(dir.path(), &discovery, None, None, None, None).valid);

        let current = SkillSignature {
            previous_hash: Some("sha256:aa".to_string()),
            ..sig.clone()
        };
        let mut previous = sig.clone();
        previous.schemapin_version = "1.3".to_string();
        previous.skill_hash = "sha256:aa".to_string();
        assert_eq!(verify_chain(&current, &previous), Err(ChainError::Legacy));
    }

    #[test]
    fn test_domain_binding() {
        let kp = generate_key_pair().unwrap();
        let dir = tempdir().unwrap();
        make_skill_dir(dir.path(), &[("SKILL.md", b"# hi")]);
        sign_skill(
            dir.path(),
            &kp.private_key_pem,
            "evil.example.com",
            None,
            None,
        )
        .unwrap();
        let discovery = build_well_known_response(&kp.public_key_pem, Some("Dev"), vec![], "1.4");
        let mut store = KeyPinStore::new();
        let r = verify_skill_offline_with_options(
            dir.path(),
            &discovery,
            None,
            None,
            Some(&mut store),
            &VerifyOptions {
                domain: Some("good.example.com"),
                tool_id: Some("calc"),
                allow_expired: false,
            },
        );
        assert_eq!(r.error_code, Some(ErrorCode::DomainMismatch));
        assert!(store.get_tool("calc", "good.example.com").is_none());
        assert!(store.get_tool("calc", "evil.example.com").is_none());

        for bad in [
            "../skills/evil/key",
            "localhost",
            "http://example.com",
            "10.0.0.1",
        ] {
            let r = verify_skill_offline_with_options(
                dir.path(),
                &discovery,
                None,
                None,
                None,
                &VerifyOptions {
                    domain: Some(bad),
                    ..VerifyOptions::default()
                },
            );
            assert_eq!(r.error_code, Some(ErrorCode::DomainInvalid), "{}", bad);
        }

        let dir2 = tempdir().unwrap();
        make_skill_dir(dir2.path(), &[("SKILL.md", b"# hi")]);
        sign_skill(dir2.path(), &kp.private_key_pem, "Example.COM", None, None).unwrap();
        let bound = verify_skill_offline_with_options(
            dir2.path(),
            &discovery,
            None,
            None,
            None,
            &VerifyOptions {
                domain: Some("example.com"),
                ..VerifyOptions::default()
            },
        );
        assert!(bound.valid);
        assert_eq!(bound.domain.as_deref(), Some("example.com"));
        assert!(!bound.warnings.iter().any(|w| w == "domain_unbound"));
        let unbound = verify_skill_offline(dir2.path(), &discovery, None, None, None, None);
        assert!(unbound.warnings.iter().any(|w| w == "domain_unbound"));
    }

    #[test]
    fn test_resolver_path_binds_domain_before_io() {
        struct Exploding;
        impl SchemaResolver for Exploding {
            fn resolve_discovery(&self, _domain: &str) -> Result<WellKnownResponse, Error> {
                panic!("network must not be touched on domain mismatch");
            }
        }
        let kp = generate_key_pair().unwrap();
        let dir = tempdir().unwrap();
        make_skill_dir(dir.path(), &[("SKILL.md", b"# hi")]);
        sign_skill(
            dir.path(),
            &kp.private_key_pem,
            "good.example.com",
            None,
            None,
        )
        .unwrap();
        let r = verify_skill_with_resolver(dir.path(), "evil.example.com", &Exploding, None, None);
        assert_eq!(r.error_code, Some(ErrorCode::DomainMismatch));
    }

    #[test]
    fn test_pin_after_verify() {
        let kp = generate_key_pair().unwrap();
        let other = generate_key_pair().unwrap();
        let dir = tempdir().unwrap();
        make_skill_dir(dir.path(), &[("SKILL.md", b"# hi")]);
        sign_skill(dir.path(), &kp.private_key_pem, "example.com", None, None).unwrap();
        let wrong = build_well_known_response(&other.public_key_pem, Some("Dev"), vec![], "1.4");
        let right = build_well_known_response(&kp.public_key_pem, Some("Dev"), vec![], "1.4");
        let mut store = KeyPinStore::new();
        let opts = VerifyOptions {
            domain: Some("example.com"),
            tool_id: Some("t"),
            allow_expired: false,
        };
        let r = verify_skill_offline_with_options(
            dir.path(),
            &wrong,
            None,
            None,
            Some(&mut store),
            &opts,
        );
        assert_eq!(r.error_code, Some(ErrorCode::SignatureInvalid));
        assert!(
            store.get_tool("t", "example.com").is_none(),
            "failed verification must not pin"
        );
        let r = verify_skill_offline_with_options(
            dir.path(),
            &right,
            None,
            None,
            Some(&mut store),
            &opts,
        );
        assert!(r.valid);
        assert_eq!(r.key_pinning.unwrap().status, "first_use");
        assert!(store.get_tool("t", "example.com").is_some());

        let dir2 = tempdir().unwrap();
        make_skill_dir(dir2.path(), &[("SKILL.md", b"# hi")]);
        let sopts = SignOptions::new().with_expires_in(-chrono::Duration::days(1));
        sign_skill_with_options(dir2.path(), &kp.private_key_pem, "example.com", sopts).unwrap();
        let mut store2 = KeyPinStore::new();
        let r = verify_skill_offline_with_options(
            dir2.path(),
            &right,
            None,
            None,
            Some(&mut store2),
            &opts,
        );
        assert!(!r.valid);
        assert!(
            store2.get_tool("t", "example.com").is_none(),
            "expired must not pin"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_symlinks_rejected() {
        let base = tempdir().unwrap();
        let dir = base.path().join("skill");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("SKILL.md"), b"# hi").unwrap();
        let kp = generate_key_pair().unwrap();
        sign_skill(&dir, &kp.private_key_pem, "example.com", None, None).unwrap();
        fs::write(base.path().join("outside.txt"), b"unsigned").unwrap();
        std::os::unix::fs::symlink(base.path().join("outside.txt"), dir.join("helper.sh")).unwrap();
        assert!(canonicalize_skill(&dir).is_err());
        let discovery = build_well_known_response(&kp.public_key_pem, Some("Dev"), vec![], "1.4");
        let r = verify_skill_offline(&dir, &discovery, None, None, None, None);
        assert_eq!(r.error_code, Some(ErrorCode::SchemaCanonicalizationFailed));
        fs::remove_file(dir.join("helper.sh")).unwrap();
        fs::create_dir_all(base.path().join("other")).unwrap();
        std::os::unix::fs::symlink(base.path().join("other"), dir.join("examples")).unwrap();
        assert!(canonicalize_skill(&dir).is_err());
    }

    #[test]
    fn test_path_content_boundary_not_malleable() {
        let a = tempdir().unwrap();
        let b = tempdir().unwrap();
        make_skill_dir(a.path(), &[("run.sh.disabled", b"\necho hi")]);
        make_skill_dir(b.path(), &[("run.sh", b".disabled\necho hi")]);
        assert_ne!(
            canonicalize_skill(a.path()).unwrap().0,
            canonicalize_skill(b.path()).unwrap().0
        );
        // The legacy algorithm collides on exactly this re-split.
        assert_eq!(
            canonicalize_skill_v1(a.path()).unwrap().0,
            canonicalize_skill_v1(b.path()).unwrap().0
        );
    }

    #[test]
    fn test_nested_sig_file_is_content() {
        let dir = tempdir().unwrap();
        make_skill_dir(
            dir.path(),
            &[("SKILL.md", b"# hi"), ("nested/.schemapin.sig", b"{}")],
        );
        let (_, manifest) = canonicalize_skill(dir.path()).unwrap();
        assert!(manifest.contains_key("nested/.schemapin.sig"));
        assert!(!manifest.contains_key(".schemapin.sig"));
    }
}
