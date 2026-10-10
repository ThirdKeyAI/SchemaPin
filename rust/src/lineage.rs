//! Verifier-side lineage store for schema-version binding (spec section 18.4).
//!
//! [`crate::skill::verify_chain`] compares two signature documents the caller
//! already holds. A verifier that wants protection against rollback and forks
//! needs to remember the *latest accepted* `skill_hash` for each tool and
//! insist that every new signature descends from it. [`LineageStore`] is that
//! memory.
//!
//! Only feed it signature documents that [`crate::skill::verify_skill_offline`]
//! has already accepted, and only `schemapin_version >= "1.4"` documents:
//! their `skill_hash`, `previous_hash` and `schema_version` are covered by the
//! signature, which is what makes the chain meaningful. Legacy 1.3 documents
//! are refused.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::skill::SkillSignature;

/// Latest accepted lineage state for a `tool_id@domain`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageRecord {
    pub skill_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<String>,
}

/// Outcome of [`LineageStore::check_and_advance`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineageResult {
    /// Nothing was recorded; the document becomes the head.
    FirstUse,
    /// The document's `skill_hash` is already the head.
    Unchanged,
    /// The document is a valid successor and is now the head.
    Advanced,
}

/// Returned when a signature does not descend from the recorded lineage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineageError(pub String);

impl std::fmt::Display for LineageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LineageError {}

fn version_key(version: &str) -> Option<[u64; 3]> {
    let v = version.strip_prefix('v').unwrap_or(version);
    let mut key = [0u64; 3];
    let mut any = false;
    for (i, part) in v.split('.').take(3).enumerate() {
        let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            break;
        }
        key[i] = digits.parse().ok()?;
        any = true;
        if digits.len() != part.len() {
            break;
        }
    }
    any.then_some(key)
}

fn is_legacy_version(version: &str) -> bool {
    let Some((major, minor)) = version.split_once('.') else {
        return false;
    };
    match (major.parse::<u32>(), minor.parse::<u32>()) {
        (Ok(ma), Ok(mi)) => (ma, mi) < (1, 4),
        _ => false,
    }
}

/// Return `true` when `current` sorts strictly after `previous`.
///
/// Numeric `major.minor.patch` prefixes compare numerically (`1.10.0` >
/// `1.9.0`); when either side is not semver-like the comparison falls back to
/// a plain string comparison, which still rejects reuse of the same value.
pub fn version_increases(previous: &str, current: &str) -> bool {
    match (version_key(previous), version_key(current)) {
        (Some(p), Some(c)) if p != c => c > p,
        _ => current > previous,
    }
}

/// In-memory `latest_known_hash` store keyed by `tool_id@domain`.
#[derive(Debug, Default, Clone)]
pub struct LineageStore {
    latest: HashMap<String, LineageRecord>,
}

impl LineageStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn key(tool_id: &str, domain: &str) -> String {
        format!("{}@{}", tool_id, domain)
    }

    /// Return the latest accepted record.
    pub fn get(&self, tool_id: &str, domain: &str) -> Option<&LineageRecord> {
        self.latest.get(&Self::key(tool_id, domain))
    }

    /// Pre-seed the latest accepted state (for example from a trusted manifest).
    pub fn seed(
        &mut self,
        tool_id: &str,
        domain: &str,
        skill_hash: &str,
        schema_version: Option<&str>,
    ) {
        self.latest.insert(
            Self::key(tool_id, domain),
            LineageRecord {
                skill_hash: skill_hash.to_string(),
                schema_version: schema_version.map(str::to_string),
            },
        );
    }

    /// Check `sig` against the lineage and advance on success. With
    /// `require_chain` a document for a known tool must carry `previous_hash`.
    pub fn check_and_advance(
        &mut self,
        tool_id: &str,
        domain: &str,
        sig: &SkillSignature,
        require_chain: bool,
    ) -> Result<LineageResult, LineageError> {
        if is_legacy_version(&sig.schemapin_version) {
            return Err(LineageError(
                "legacy 1.3 signature documents carry an unsigned skill_hash and cannot anchor a lineage".to_string(),
            ));
        }
        if sig.skill_hash.is_empty() {
            return Err(LineageError(
                "signature document has no skill_hash".to_string(),
            ));
        }
        let key = Self::key(tool_id, domain);
        let Some(record) = self.latest.get(&key).cloned() else {
            self.latest.insert(
                key,
                LineageRecord {
                    skill_hash: sig.skill_hash.clone(),
                    schema_version: sig.schema_version.clone(),
                },
            );
            return Ok(LineageResult::FirstUse);
        };
        if record.skill_hash == sig.skill_hash {
            return Ok(LineageResult::Unchanged);
        }
        match sig.previous_hash.as_deref() {
            None if require_chain => {
                return Err(LineageError(format!(
                    "signature for {} has no previous_hash; expected a descendant of {}",
                    key, record.skill_hash
                )));
            }
            Some(prev) if prev != record.skill_hash => {
                return Err(LineageError(format!(
                    "previous_hash {} does not match the latest accepted skill_hash {} for {} (fork or rollback)",
                    prev, record.skill_hash, key
                )));
            }
            _ => {}
        }
        if let (Some(cur), Some(prev)) = (&sig.schema_version, &record.schema_version) {
            if !version_increases(prev, cur) {
                return Err(LineageError(format!(
                    "schema_version {:?} does not increase over {:?} for {}",
                    cur, prev, key
                )));
            }
        }
        self.latest.insert(
            key,
            LineageRecord {
                skill_hash: sig.skill_hash.clone(),
                schema_version: sig.schema_version.clone(),
            },
        );
        Ok(LineageResult::Advanced)
    }

    /// Serialize the store to JSON.
    pub fn to_json(&self) -> Result<String, Error> {
        Ok(serde_json::to_string(&self.latest)?)
    }

    /// Deserialize a store from JSON.
    pub fn from_json(json: &str) -> Result<Self, Error> {
        let latest: HashMap<String, LineageRecord> = serde_json::from_str(json)?;
        if latest.values().any(|r| r.skill_hash.is_empty()) {
            return Err(Error::Verification {
                code: crate::error::ErrorCode::SignatureInvalid,
                message: "lineage store entries must carry a skill_hash".to_string(),
            });
        }
        Ok(Self { latest })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn doc(
        hash: &str,
        previous: Option<&str>,
        version: Option<&str>,
        schemapin: &str,
    ) -> SkillSignature {
        SkillSignature {
            schemapin_version: schemapin.to_string(),
            skill_name: "calc".to_string(),
            skill_hash: hash.to_string(),
            signature: String::new(),
            signed_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: None,
            schema_version: version.map(str::to_string),
            previous_hash: previous.map(str::to_string),
            canonicalization: None,
            domain: "example.com".to_string(),
            signer_kid: String::new(),
            file_manifest: BTreeMap::new(),
        }
    }

    #[test]
    fn flow_first_use_advance_unchanged() {
        let mut s = LineageStore::new();
        assert_eq!(
            s.check_and_advance(
                "calc",
                "example.com",
                &doc("sha256:a", None, Some("1.0.0"), "1.4"),
                true
            ),
            Ok(LineageResult::FirstUse)
        );
        assert_eq!(
            s.check_and_advance(
                "calc",
                "example.com",
                &doc("sha256:a", None, Some("1.0.0"), "1.4"),
                true
            ),
            Ok(LineageResult::Unchanged)
        );
        assert_eq!(
            s.check_and_advance(
                "calc",
                "example.com",
                &doc("sha256:b", Some("sha256:a"), Some("1.1.0"), "1.4"),
                true
            ),
            Ok(LineageResult::Advanced)
        );
        assert_eq!(s.get("calc", "example.com").unwrap().skill_hash, "sha256:b");
    }

    #[test]
    fn forks_rollbacks_versions_and_legacy() {
        let mut s = LineageStore::new();
        s.check_and_advance(
            "calc",
            "example.com",
            &doc("sha256:v4", None, Some("1.9.0"), "1.4"),
            true,
        )
        .unwrap();
        s.check_and_advance(
            "calc",
            "example.com",
            &doc("sha256:v5", Some("sha256:v4"), Some("1.9.1"), "1.4"),
            true,
        )
        .unwrap();
        assert!(s
            .check_and_advance(
                "calc",
                "example.com",
                &doc("sha256:v5x", Some("sha256:v4"), None, "1.4"),
                true
            )
            .is_err());
        assert!(s
            .check_and_advance(
                "calc",
                "example.com",
                &doc("sha256:v6", None, None, "1.4"),
                true
            )
            .is_err());
        assert!(s
            .check_and_advance(
                "calc",
                "example.com",
                &doc("sha256:v6", Some("sha256:v5"), Some("1.9.1"), "1.4"),
                true
            )
            .is_err());
        assert!(s
            .check_and_advance(
                "calc",
                "example.com",
                &doc("sha256:v6", Some("sha256:v5"), Some("1.2.0"), "1.4"),
                true
            )
            .is_err());
        assert_eq!(
            s.check_and_advance(
                "calc",
                "example.com",
                &doc("sha256:v6", Some("sha256:v5"), Some("1.10.0"), "1.4"),
                true
            ),
            Ok(LineageResult::Advanced)
        );
        assert!(s
            .check_and_advance(
                "calc",
                "example.com",
                &doc("sha256:z", Some("sha256:v6"), None, "1.3"),
                true
            )
            .is_err());
        assert!(version_increases("1.9.0", "1.10.0"));
        assert!(!version_increases("2.0.0", "2.0.0"));
        assert!(version_increases("abc", "abd"));
        let restored = LineageStore::from_json(&s.to_json().unwrap()).unwrap();
        assert_eq!(
            restored
                .get("calc", "example.com")
                .unwrap()
                .schema_version
                .as_deref(),
            Some("1.10.0")
        );
        assert!(LineageStore::from_json("[]").is_err());
    }
}
