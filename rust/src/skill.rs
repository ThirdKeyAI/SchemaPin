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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillSignature {
    pub schemapin_version: String,
    pub skill_name: String,
    pub skill_hash: String,
    pub signature: String,
    pub signed_at: String,
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

/// Sign a skill directory and write `.schemapin.sig`.
///
/// Returns the signature document that was written.
pub fn sign_skill(
    skill_dir: &Path,
    private_key_pem: &str,
    domain: &str,
    signer_kid: Option<&str>,
    skill_name: Option<&str>,
) -> Result<SkillSignature, Error> {
    let (root_hash, manifest) = canonicalize_skill(skill_dir)?;

    let name = match skill_name {
        Some(n) => n.to_string(),
        None => parse_skill_name(skill_dir),
    };

    let kid = match signer_kid {
        Some(k) => k.to_string(),
        None => {
            // Derive public key from private, then compute fingerprint
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

    let sig_doc = SkillSignature {
        schemapin_version: "1.3".to_string(),
        skill_name: name,
        skill_hash,
        signature: signature_b64,
        signed_at: chrono::Utc::now().to_rfc3339(),
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
}
