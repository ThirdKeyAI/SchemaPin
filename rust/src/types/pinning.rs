use serde::{Deserialize, Serialize};

/// A pinned tool with its associated domain and keys.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinnedTool {
    pub tool_id: String,
    pub domain: String,
    pub pinned_keys: Vec<PinnedKey>,
}

/// A single pinned key entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinnedKey {
    pub fingerprint: String,
    pub first_seen: String,
    pub last_seen: String,
    pub trust_level: TrustLevel,
}

/// Trust level for a pinned key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustLevel {
    Tofu,
    Verified,
    Pinned,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pinned_tool_serde_roundtrip() {
        let pt = PinnedTool {
            tool_id: "calculate_sum".to_string(),
            domain: "example.com".to_string(),
            pinned_keys: vec![PinnedKey {
                fingerprint: "sha256:abcdef1234567890".to_string(),
                first_seen: "2026-01-15T00:00:00Z".to_string(),
                last_seen: "2026-01-30T00:00:00Z".to_string(),
                trust_level: TrustLevel::Tofu,
            }],
        };
        let json = serde_json::to_string(&pt).unwrap();
        let pt2: PinnedTool = serde_json::from_str(&json).unwrap();
        assert_eq!(pt, pt2);
    }

    #[test]
    fn test_trust_level_serde() {
        assert_eq!(
            serde_json::to_string(&TrustLevel::Tofu).unwrap(),
            "\"tofu\""
        );
        assert_eq!(
            serde_json::to_string(&TrustLevel::Verified).unwrap(),
            "\"verified\""
        );
        assert_eq!(
            serde_json::to_string(&TrustLevel::Pinned).unwrap(),
            "\"pinned\""
        );
    }
}
