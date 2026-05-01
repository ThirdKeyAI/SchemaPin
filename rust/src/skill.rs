//! Skill directory signing and verification.
//!
//! Mirrors the Python `SkillSigner` class: same canonicalization algorithm,
//! same `.schemapin.sig` format, cross-language interop.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use p256::pkcs8::{DecodePrivateKey, EncodePublicKey};

use crate::crypto;
use crate::discovery::validate_well_known_response;
use crate::error::{Error, ErrorCode};
use crate::pinning::{check_pinning, KeyPinStore, PinningResult};
use crate::resolver::SchemaResolver;
use crate::revocation::check_revocation_combined;
use crate::types::discovery::WellKnownResponse;
use crate::types::revocation::RevocationDocument;
use crate::verification::{KeyPinningStatus, VerificationResult};

/// Signature metadata written to `.schemapin.sig`.
///
/// Optional v1.4 fields:
/// - `expires_at` — verifiers past the expiration emit a `signature_expired` warning
///   (see [`verify_skill_offline`]); they do not fail.
/// - `schema_version` — caller-supplied semver string identifying *this* version of
///   the signed artifact (e.g. `"2.1.0"`). Returned via [`crate::verification::VerificationResult`]
///   so consumers can apply their own version policy.
/// - `previous_hash` — SHA-256 hash (`sha256:<hex>`) of the *prior* signed version's
///   `skill_hash`, forming a hash chain. Use [`verify_chain`] to confirm a new signature
///   descends from a specific prior signature.
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

/// Recursively walk a directory in sorted order, producing a deterministic
/// file manifest and root hash.
///
/// Returns `(root_hash_bytes, manifest)` where each manifest entry maps
/// a forward-slash relative path to `"sha256:<hex>"`.
pub fn canonicalize_skill(skill_dir: &Path) -> Result<(Vec<u8>, BTreeMap<String, String>), Error> {
    let mut manifest = BTreeMap::new();
    walk_sorted(skill_dir, skill_dir, &mut manifest)?;

    if manifest.is_empty() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "skill directory contains no files",
        )));
    }

    // Root hash: sort keys, concat hex digests, SHA-256
    let joined: String = manifest
        .values()
        .map(|v| v.strip_prefix("sha256:").unwrap_or(v))
        .collect::<Vec<_>>()
        .join("");

    let root_hash = Sha256::digest(joined.as_bytes()).to_vec();
    Ok((root_hash, manifest))
}

/// Recursive sorted directory walk.
fn walk_sorted(
    base: &Path,
    dir: &Path,
    manifest: &mut BTreeMap<String, String>,
) -> Result<(), Error> {
    let mut entries: Vec<fs::DirEntry> = fs::read_dir(dir)?.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)?;

        // Skip symlinks
        if meta.is_symlink() {
            continue;
        }

        if meta.is_dir() {
            walk_sorted(base, &path, manifest)?;
        } else if meta.is_file() {
            let file_name = entry.file_name();
            if file_name == ".schemapin.sig" {
                continue;
            }

            let rel = path
                .strip_prefix(base)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
            // Forward-slash normalize
            let rel_str = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");

            let file_bytes = fs::read(&path)?;
            let mut hasher = Sha256::new();
            hasher.update(rel_str.as_bytes());
            hasher.update(&file_bytes);
            let digest = hex::encode(hasher.finalize());

            manifest.insert(rel_str, format!("sha256:{}", digest));
        }
    }
    Ok(())
}

/// Extract the skill name from `SKILL.md` frontmatter, falling back to the
/// directory basename.
///
/// Parses YAML frontmatter (`---` delimited) and looks for a `name:` field.
/// No regex crate needed — pure string operations.
pub fn parse_skill_name(skill_dir: &Path) -> String {
    let skill_md = skill_dir.join("SKILL.md");
    if let Ok(text) = fs::read_to_string(&skill_md) {
        if let Some(name) = extract_frontmatter_name(&text) {
            return name;
        }
    }
    // Fallback: directory basename
    skill_dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".to_string())
}

/// String-based frontmatter `name:` extraction (no regex).
fn extract_frontmatter_name(text: &str) -> Option<String> {
    // Must start with "---\n" (or "---\r\n")
    let text = text.trim_start_matches('\u{feff}'); // strip BOM
    if !text.starts_with("---") {
        return None;
    }
    let after_open = &text[3..];
    let after_open = after_open.strip_prefix('\r').unwrap_or(after_open);
    let after_open = after_open.strip_prefix('\n')?;

    // Find closing "---"
    let close_idx = after_open.find("\n---")?;
    let frontmatter = &after_open[..close_idx];

    for line in frontmatter.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("name:") {
            let val = rest.trim();
            // Strip surrounding quotes
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
    let sig_path = skill_dir.join(".schemapin.sig");
    let data = fs::read_to_string(&sig_path)?;
    let sig: SkillSignature = serde_json::from_str(&data)?;
    Ok(sig)
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
    /// Time-to-live for the signature. When set, an `expires_at` field is written.
    pub expires_in: Option<chrono::Duration>,
    /// Caller-supplied semver string identifying *this* version of the signed artifact.
    /// Written to `schema_version` and surfaced on [`crate::verification::VerificationResult`].
    pub schema_version: Option<&'a str>,
    /// `sha256:<hex>` hash of the *prior* signed version's `skill_hash`, forming a chain.
    /// When set, written to `previous_hash`. Pair with [`verify_chain`] at verify time.
    pub previous_hash: Option<&'a str>,
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
}

/// Sign a skill directory and write `.schemapin.sig`.
///
/// Convenience wrapper over [`sign_skill_with_options`] preserved for v1.3 callers.
/// Returns the signature document that was written.
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
            expires_in: None,
            schema_version: None,
            previous_hash: None,
        },
    )
}

/// Sign a skill directory with extended options (v1.4+).
///
/// When `options.expires_in` is `Some(ttl)`, an `expires_at` ISO 8601 timestamp
/// is written. Verifiers past that timestamp emit a warning instead of failing
/// (see [`verify_skill_offline`]).
pub fn sign_skill_with_options(
    skill_dir: &Path,
    private_key_pem: &str,
    domain: &str,
    options: SignOptions<'_>,
) -> Result<SkillSignature, Error> {
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

    let signature_b64 = crypto::sign_data(private_key_pem, &root_hash)?;
    let skill_hash = format!("sha256:{}", hex::encode(Sha256::digest(&root_hash)));

    let now = chrono::Utc::now();
    let expires_at = options
        .expires_in
        .map(|ttl| (now + ttl).to_rfc3339_opts(chrono::SecondsFormat::Secs, true));

    let schema_version = options.schema_version.map(str::to_string);
    let previous_hash = options.previous_hash.map(str::to_string);

    // Any v1.4 optional field bumps the version stamp; pure v1.3 sigs stay "1.3"
    // for byte-stable backward compatibility.
    let uses_v1_4_field =
        expires_at.is_some() || schema_version.is_some() || previous_hash.is_some();
    let version = if uses_v1_4_field { "1.4" } else { "1.3" };

    let sig_doc = SkillSignature {
        schemapin_version: version.to_string(),
        skill_name: name,
        skill_hash,
        signature: signature_b64,
        signed_at: now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        expires_at,
        schema_version,
        previous_hash,
        domain: domain.to_string(),
        signer_kid: kid,
        file_manifest: manifest,
    };

    let sig_path = skill_dir.join(".schemapin.sig");
    let json = serde_json::to_string_pretty(&sig_doc)?;
    fs::write(&sig_path, format!("{}\n", json))?;

    Ok(sig_doc)
}

/// Offline 7-step skill verification, mirroring `verify_schema_offline`.
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

    // Step 2: Validate discovery document
    if let Err(e) = validate_well_known_response(discovery) {
        return VerificationResult::failure(
            ErrorCode::DiscoveryInvalid,
            &format!("Discovery validation failed: {}", e),
        );
    }

    // Step 3: Extract public key and compute fingerprint
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

    // Step 5: TOFU key pinning
    let effective_tool_id = tool_id
        .map(|s| s.to_string())
        .unwrap_or_else(|| sig.skill_name.clone());
    let pin_result = if let Some(store) = pin_store {
        match check_pinning(store, &effective_tool_id, &sig.domain, &fingerprint) {
            Ok(r) => Some((r, store as &KeyPinStore)),
            Err(e) => {
                return VerificationResult::failure(ErrorCode::KeyPinMismatch, &e.to_string());
            }
        }
    } else {
        None
    };

    // Step 6: Canonicalize and verify signature
    let (root_hash, _manifest) = match canonicalize_skill(skill_dir) {
        Ok(v) => v,
        Err(e) => {
            return VerificationResult::failure(
                ErrorCode::SchemaCanonicalizationFailed,
                &format!("Skill canonicalization failed: {}", e),
            );
        }
    };

    let valid =
        match crypto::verify_signature(&discovery.public_key_pem, &root_hash, &sig.signature) {
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

    // Step 7: Build success result
    let pin_status = match pin_result {
        Some((PinningResult::FirstUse, _)) => KeyPinningStatus {
            status: "first_use".to_string(),
            first_seen: Some(chrono::Utc::now().to_rfc3339()),
        },
        Some((PinningResult::Matched, store)) => {
            let first_seen = store
                .get_tool(&effective_tool_id, &sig.domain)
                .and_then(|t| t.pinned_keys.first())
                .map(|pk| pk.first_seen.clone());
            KeyPinningStatus {
                status: "pinned".to_string(),
                first_seen,
            }
        }
        Some((PinningResult::Changed, _)) => {
            unreachable!("Changed case handled above")
        }
        None => KeyPinningStatus {
            status: "first_use".to_string(),
            first_seen: Some(chrono::Utc::now().to_rfc3339()),
        },
    };

    VerificationResult::success(&sig.domain, discovery.developer_name.as_deref(), pin_status)
        .with_expiration_check(sig.expires_at.as_deref())
        .with_lineage_metadata(sig.schema_version.as_deref(), sig.previous_hash.as_deref())
}

/// Errors returned by [`verify_chain`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// `current.previous_hash` is absent — the new signature doesn't claim a predecessor.
    NoPreviousHash,
    /// `current.previous_hash` is present but doesn't match `previous.skill_hash`.
    Mismatch { expected: String, got: String },
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
        }
    }
}

impl std::error::Error for ChainError {}

/// Verify that `current` is the legitimate successor of `previous` via the
/// `previous_hash` lineage chain (v1.4 alpha.2).
///
/// Returns `Ok(())` when `current.previous_hash == Some(previous.skill_hash)`.
///
/// This is a pure-metadata check — no cryptography is re-evaluated. Both signatures
/// must already be cryptographically verified separately via [`verify_skill_offline`]
/// for the chain check to be meaningful.
///
/// Use this to defend against rug-pull attacks where an attacker substitutes a
/// schema/skill out-of-band: a legitimate update declares the prior version's hash;
/// an unauthorized substitution either omits `previous_hash` or points at a hash
/// the verifier hasn't accepted as a valid ancestor.
pub fn verify_chain(current: &SkillSignature, previous: &SkillSignature) -> Result<(), ChainError> {
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
/// Behaves identically to [`verify_skill_offline`], then — when `dns_txt` is
/// `Some` — verifies that the DNS TXT record's fingerprint matches the
/// discovery key. A mismatch converts the result into a hard failure with
/// [`ErrorCode::DomainMismatch`]. When `dns_txt` is `None`, behaviour is
/// unchanged (DNS TXT is an optional, additive trust signal).
pub fn verify_skill_offline_with_dns(
    skill_dir: &Path,
    discovery: &WellKnownResponse,
    signature_data: Option<&SkillSignature>,
    revocation_doc: Option<&RevocationDocument>,
    pin_store: Option<&mut KeyPinStore>,
    tool_id: Option<&str>,
    dns_txt: Option<&crate::dns::DnsTxtRecord>,
) -> VerificationResult {
    let result = verify_skill_offline(
        skill_dir,
        discovery,
        signature_data,
        revocation_doc,
        pin_store,
        tool_id,
    );

    if !result.valid {
        return result;
    }
    let Some(txt) = dns_txt else {
        return result;
    };
    match crate::dns::verify_dns_match(discovery, txt) {
        Ok(()) => result,
        Err(crate::error::Error::Verification { code, message }) => {
            VerificationResult::failure(code, &message)
        }
        Err(e) => VerificationResult::failure(ErrorCode::DomainMismatch, &e.to_string()),
    }
}

/// Resolve discovery via a [`SchemaResolver`], then delegate to
/// [`verify_skill_offline`].
pub fn verify_skill_with_resolver(
    skill_dir: &Path,
    domain: &str,
    resolver: &dyn SchemaResolver,
    pin_store: Option<&mut KeyPinStore>,
    tool_id: Option<&str>,
) -> VerificationResult {
    let discovery = match resolver.resolve_discovery(domain) {
        Ok(doc) => doc,
        Err(e) => {
            return VerificationResult::failure(
                ErrorCode::DiscoveryFetchFailed,
                &format!("Failed to resolve discovery document: {}", e),
            );
        }
    };

    let revocation = match resolver.resolve_revocation(domain, &discovery) {
        Ok(doc) => doc,
        Err(_) => {
            return VerificationResult::failure(
                ErrorCode::DiscoveryFetchFailed,
                "Revocation document unreachable (fail-closed)",
            );
        }
    };

    verify_skill_offline(
        skill_dir,
        &discovery,
        None,
        revocation.as_ref(),
        pin_store,
        tool_id,
    )
}

/// Compare two file manifests and report differences.
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
        assert_eq!(sig.schemapin_version, "1.3");
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
    fn test_verify_with_past_ttl_passes_with_expired_warning() {
        // Sign normally, then rewrite the .schemapin.sig with a past expires_at.
        let dir = tempdir().unwrap();
        make_skill_dir(dir.path(), &[("SKILL.md", b"---\nname: past\n---\n")]);
        let kp = generate_key_pair().unwrap();
        let mut sig =
            sign_skill(dir.path(), &kp.private_key_pem, "example.com", None, None).unwrap();
        sig.expires_at = Some(
            (chrono::Utc::now() - chrono::Duration::days(1))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        );
        sig.schemapin_version = "1.4".to_string();
        let json = serde_json::to_string_pretty(&sig).unwrap();
        fs::write(dir.path().join(".schemapin.sig"), format!("{}\n", json)).unwrap();

        let discovery = build_well_known_response(&kp.public_key_pem, Some("Dev"), vec![], "1.3");
        let result = verify_skill_offline(dir.path(), &discovery, None, None, None, Some("past"));
        assert!(result.valid, "expired sigs are degraded, not failed");
        assert!(result.expired);
        assert!(result.warnings.iter().any(|w| w == "signature_expired"));
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
    fn test_verify_with_unparseable_expires_at_warns() {
        let dir = tempdir().unwrap();
        make_skill_dir(dir.path(), &[("SKILL.md", b"---\nname: bad\n---\n")]);
        let kp = generate_key_pair().unwrap();
        let mut sig =
            sign_skill(dir.path(), &kp.private_key_pem, "example.com", None, None).unwrap();
        sig.expires_at = Some("not-a-timestamp".to_string());
        let json = serde_json::to_string_pretty(&sig).unwrap();
        fs::write(dir.path().join(".schemapin.sig"), format!("{}\n", json)).unwrap();

        let discovery = build_well_known_response(&kp.public_key_pem, Some("Dev"), vec![], "1.3");
        let result = verify_skill_offline(dir.path(), &discovery, None, None, None, Some("bad"));
        assert!(result.valid);
        assert!(!result.expired);
        assert!(result
            .warnings
            .iter()
            .any(|w| w == "signature_expires_at_unparseable"));
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
}
