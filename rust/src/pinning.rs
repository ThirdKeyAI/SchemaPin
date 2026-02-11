use std::collections::HashMap;

use chrono::Utc;

use crate::error::{Error, ErrorCode};
use crate::types::pinning::{PinnedKey, PinnedTool, TrustLevel};

/// Result of checking a key against the pin store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinningResult {
    /// First time seeing this tool@domain — key has been pinned.
    FirstUse,
    /// Tool@domain seen before and key matches a pinned key.
    Matched,
    /// Tool@domain seen before but key does NOT match any pinned key.
    Changed,
}

/// In-memory TOFU key pinning store, keyed by `"tool_id@domain"`.
#[derive(Debug, Clone, Default)]
pub struct KeyPinStore {
    tools: HashMap<String, PinnedTool>,
}

impl KeyPinStore {
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
        }
    }

    /// Composite key for the store.
    fn composite_key(tool_id: &str, domain: &str) -> String {
        format!("{}@{}", tool_id, domain)
    }

    /// Check a key fingerprint against the pin store. If this is the first time
    /// seeing this tool@domain, the key is pinned (TOFU). Returns the pinning result.
    pub fn check_and_pin(
        &mut self,
        tool_id: &str,
        domain: &str,
        fingerprint: &str,
    ) -> PinningResult {
        let key = Self::composite_key(tool_id, domain);
        let now = Utc::now().to_rfc3339();

        if let Some(pinned) = self.tools.get_mut(&key) {
            // Tool@domain previously seen — check if key matches
            if let Some(pk) = pinned
                .pinned_keys
                .iter_mut()
                .find(|pk| pk.fingerprint == fingerprint)
            {
                pk.last_seen = now;
                PinningResult::Matched
            } else {
                PinningResult::Changed
            }
        } else {
            // First time seeing this tool@domain — TOFU pin
            self.tools.insert(
                key,
                PinnedTool {
                    tool_id: tool_id.to_string(),
                    domain: domain.to_string(),
                    pinned_keys: vec![PinnedKey {
                        fingerprint: fingerprint.to_string(),
                        first_seen: now.clone(),
                        last_seen: now,
                        trust_level: TrustLevel::Tofu,
                    }],
                },
            );
            PinningResult::FirstUse
        }
    }

    /// Add a key to an existing tool@domain's pin set (e.g., during key rotation).
    pub fn add_key(&mut self, tool_id: &str, domain: &str, fingerprint: &str) {
        let key = Self::composite_key(tool_id, domain);
        let now = Utc::now().to_rfc3339();

        let pinned = self.tools.entry(key).or_insert_with(|| PinnedTool {
            tool_id: tool_id.to_string(),
            domain: domain.to_string(),
            pinned_keys: vec![],
        });

        if !pinned
            .pinned_keys
            .iter()
            .any(|pk| pk.fingerprint == fingerprint)
        {
            pinned.pinned_keys.push(PinnedKey {
                fingerprint: fingerprint.to_string(),
                first_seen: now.clone(),
                last_seen: now,
                trust_level: TrustLevel::Tofu,
            });
        }
    }

    /// Get pinned tool info.
    pub fn get_tool(&self, tool_id: &str, domain: &str) -> Option<&PinnedTool> {
        let key = Self::composite_key(tool_id, domain);
        self.tools.get(&key)
    }

    /// Serialize the store to JSON.
    pub fn to_json(&self) -> Result<String, Error> {
        let tools: Vec<&PinnedTool> = self.tools.values().collect();
        Ok(serde_json::to_string_pretty(&tools)?)
    }

    /// Deserialize the store from JSON.
    pub fn from_json(json: &str) -> Result<Self, Error> {
        let tools: Vec<PinnedTool> = serde_json::from_str(json)?;
        let map = tools
            .into_iter()
            .map(|t| (Self::composite_key(&t.tool_id, &t.domain), t))
            .collect();
        Ok(Self { tools: map })
    }
}

/// Check pinning and return an error if key has changed (for use in verification flow).
pub fn check_pinning(
    store: &mut KeyPinStore,
    tool_id: &str,
    domain: &str,
    fingerprint: &str,
) -> Result<PinningResult, Error> {
    let result = store.check_and_pin(tool_id, domain, fingerprint);
    if result == PinningResult::Changed {
        return Err(Error::Verification {
            code: ErrorCode::KeyPinMismatch,
            message: format!(
                "Key for '{}@{}' has changed since last pinned (fingerprint: '{}')",
                tool_id, domain, fingerprint
            ),
        });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_use_pins_key() {
        let mut store = KeyPinStore::new();
        let result = store.check_and_pin("calc", "example.com", "sha256:key1");
        assert_eq!(result, PinningResult::FirstUse);

        // Second time should match
        let result = store.check_and_pin("calc", "example.com", "sha256:key1");
        assert_eq!(result, PinningResult::Matched);
    }

    #[test]
    fn test_key_change_detected() {
        let mut store = KeyPinStore::new();
        store.check_and_pin("calc", "example.com", "sha256:key1");

        let result = store.check_and_pin("calc", "example.com", "sha256:key2");
        assert_eq!(result, PinningResult::Changed);
    }

    #[test]
    fn test_add_key_allows_rotation() {
        let mut store = KeyPinStore::new();
        store.check_and_pin("calc", "example.com", "sha256:key1");

        store.add_key("calc", "example.com", "sha256:key2");

        assert_eq!(
            store.check_and_pin("calc", "example.com", "sha256:key1"),
            PinningResult::Matched
        );
        assert_eq!(
            store.check_and_pin("calc", "example.com", "sha256:key2"),
            PinningResult::Matched
        );
    }

    #[test]
    fn test_json_roundtrip() {
        let mut store = KeyPinStore::new();
        store.check_and_pin("calc", "example.com", "sha256:key1");

        let json = store.to_json().unwrap();
        let store2 = KeyPinStore::from_json(&json).unwrap();

        assert!(store2.get_tool("calc", "example.com").is_some());
        assert_eq!(
            store2
                .get_tool("calc", "example.com")
                .unwrap()
                .pinned_keys
                .len(),
            1
        );
    }

    #[test]
    fn test_check_pinning_error_on_change() {
        let mut store = KeyPinStore::new();
        store.check_and_pin("calc", "example.com", "sha256:key1");

        let result = check_pinning(&mut store, "calc", "example.com", "sha256:key2");
        assert!(result.is_err());
    }

    #[test]
    fn test_different_tools_independent() {
        let mut store = KeyPinStore::new();
        store.check_and_pin("tool_a", "example.com", "sha256:key1");
        store.check_and_pin("tool_b", "example.com", "sha256:key2");

        assert_eq!(
            store.check_and_pin("tool_a", "example.com", "sha256:key1"),
            PinningResult::Matched
        );
        assert_eq!(
            store.check_and_pin("tool_b", "example.com", "sha256:key2"),
            PinningResult::Matched
        );
        // Cross-tool should fail
        assert_eq!(
            store.check_and_pin("tool_a", "example.com", "sha256:key2"),
            PinningResult::Changed
        );
    }

    #[test]
    fn test_different_domains_independent() {
        let mut store = KeyPinStore::new();
        store.check_and_pin("calc", "a.com", "sha256:key1");
        store.check_and_pin("calc", "b.com", "sha256:key2");

        assert_eq!(
            store.check_and_pin("calc", "a.com", "sha256:key1"),
            PinningResult::Matched
        );
        assert_eq!(
            store.check_and_pin("calc", "b.com", "sha256:key2"),
            PinningResult::Matched
        );
    }
}
