//! Cross-language interop: skill-directory fixtures shared by every SDK
//! (see ../../tests/cross-language/README.md).

use std::path::{Path, PathBuf};

use schemapin::skill::{
    canonicalize_skill, canonicalize_skill_v1, load_signature, verify_skill_offline,
    verify_skill_offline_with_options, VerifyOptions,
};
use schemapin::types::discovery::WellKnownResponse;

#[derive(serde::Deserialize)]
struct Expected {
    domain: String,
    discovery: WellKnownResponse,
    v14: SkillExpected,
    legacy_v13: SkillExpected,
}

#[derive(serde::Deserialize)]
struct SkillExpected {
    skill_dir: String,
    skill_hash: String,
    file_manifest: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    signed_fields_tamper_must_fail: Vec<String>,
}

fn fixtures() -> (PathBuf, Expected) {
    let root = Path::new("../tests/cross-language/skill").to_path_buf();
    let text = std::fs::read_to_string(root.join("expected.json")).expect("fixture present");
    (root, serde_json::from_str(&text).unwrap())
}

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let target = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

#[test]
fn v14_fixture_hashes_and_verifies() {
    let (root, exp) = fixtures();
    let dir = root.join(&exp.v14.skill_dir);
    let (root_hash, manifest) = canonicalize_skill(&dir).unwrap();
    assert_eq!(
        format!("sha256:{}", hex::encode(root_hash)),
        exp.v14.skill_hash
    );
    assert_eq!(manifest, exp.v14.file_manifest);
    let r = verify_skill_offline_with_options(
        &dir,
        &exp.discovery,
        None,
        None,
        None,
        &VerifyOptions {
            domain: Some(&exp.domain),
            ..VerifyOptions::default()
        },
    );
    assert!(r.valid, "{:?}", r);
    assert!(!r.warnings.iter().any(|w| w == "legacy_signature_format"));
    assert_eq!(r.schema_version.as_deref(), Some("1.0.0"));
}

#[test]
fn v14_fixture_tampered_fields_fail() {
    let (root, exp) = fixtures();
    let src = root.join(&exp.v14.skill_dir);
    let tmp = tempfile::tempdir().unwrap();
    for field in &exp.v14.signed_fields_tamper_must_fail {
        let dst = tmp.path().join(field);
        copy_dir(&src, &dst);
        let raw = std::fs::read_to_string(dst.join(".schemapin.sig")).unwrap();
        let mut doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
        doc[field] = serde_json::Value::String(if field == "skill_hash" {
            format!("sha256:{}", "00".repeat(32))
        } else {
            "tampered".to_string()
        });
        std::fs::write(dst.join(".schemapin.sig"), doc.to_string()).unwrap();
        let r = verify_skill_offline(&dst, &exp.discovery, None, None, None, None);
        assert!(!r.valid, "tampering {} must fail", field);
    }
    let dst = tmp.path().join("content");
    copy_dir(&src, &dst);
    std::fs::write(dst.join("scripts/run.sh"), "#!/bin/sh\nrm -rf /\n").unwrap();
    assert!(!verify_skill_offline(&dst, &exp.discovery, None, None, None, None).valid);
    // The signature document itself loads fine; only verification rejects it.
    assert!(load_signature(&dst).is_ok());
}

#[test]
fn legacy_v13_fixture_verifies_with_warning() {
    let (root, exp) = fixtures();
    let dir = root.join(&exp.legacy_v13.skill_dir);
    let (root_hash, manifest) = canonicalize_skill_v1(&dir).unwrap();
    assert_eq!(
        format!("sha256:{}", hex::encode(root_hash)),
        exp.legacy_v13.skill_hash
    );
    assert_eq!(manifest, exp.legacy_v13.file_manifest);
    let r = verify_skill_offline_with_options(
        &dir,
        &exp.discovery,
        None,
        None,
        None,
        &VerifyOptions {
            domain: Some(&exp.domain),
            ..VerifyOptions::default()
        },
    );
    assert!(r.valid, "{:?}", r);
    assert!(r.warnings.iter().any(|w| w == "legacy_signature_format"));
}
