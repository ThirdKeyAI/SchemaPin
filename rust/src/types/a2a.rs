//! A2A verification context types (v1.4).
//!
//! SchemaPin verifies tool schemas. When a tool invocation crosses an A2A
//! (Agent-to-Agent) trust boundary, the verifier needs to scope the result
//! to the intersection of *caller-trusted* domains and the *tool provider's*
//! domain. This module defines [`A2aVerificationContext`] and the
//! [`AllowedDomains`] helpers used to compute that intersection.
//!
//! ## AllowedDomains convention
//!
//! The allow-list semantics mirror AgentPin v0.3 (§4.11 of the AgentPin
//! technical specification) **exactly**:
//!
//! > **An empty `AllowedDomains` list means *unrestricted* (all domains
//! > trusted).**
//!
//! This is the opposite of the naïve set-theoretic interpretation (where an
//! empty set allows nothing) but matches the existing v1.3 behaviour where
//! an *omitted* `allowed_domains` field allowed all domains. It lets
//! callers pass `Vec::new()` to mean "no restriction" without inventing a
//! sentinel.
//!
//! SchemaPin defines these helpers locally rather than depending on the
//! AgentPin crate — keeping SchemaPin self-contained for users who only
//! consume tool-integrity, and avoiding a circular trust-stack dependency.
//! Callers who *do* link both SDKs can pass the result of
//! `agentpin::AllowedDomains::intersect(...)` into
//! [`A2aVerificationContext::trusted_domains`] verbatim — the wire and
//! in-memory shapes are identical.

use serde::{Deserialize, Serialize};

/// Information that scopes a schema verification to an A2A interaction.
///
/// Pair with [`crate::verification::verify_schema_for_a2a`] to run the
/// standard 7-step verification flow with the additional A2A scope check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aVerificationContext {
    /// Caller's agent identity (URN-style, matching AgentPin).
    ///
    /// Informational only — SchemaPin does not validate the URN shape or
    /// check it against an external identity provider. The field exists so
    /// downstream policy engines (Symbiont) can correlate verification
    /// results with the originating caller.
    pub caller_agent_id: String,

    /// Depth in the A2A delegation chain. `0` means direct caller.
    ///
    /// Verifiers SHOULD reject `delegation_depth > 3` to match the AgentPin
    /// `max_delegation_depth` cap (AgentPin spec §4.3). The check is
    /// performed inside [`crate::verification::verify_schema_for_a2a`].
    pub delegation_depth: u8,

    /// Originating domain of the A2A request. Informational; the scope check
    /// uses `trusted_domains` ∩ {tool provider domain}, not this field.
    pub originating_domain: String,

    /// Caller-trusted domains.
    ///
    /// Uses the AgentPin convention: **an empty `Vec` means *unrestricted***
    /// (all domains trusted), not "deny-all". See module-level docs.
    pub trusted_domains: Vec<String>,
}

impl A2aVerificationContext {
    /// Construct a context that places no restriction on which provider
    /// domains may be verified through.
    pub fn unrestricted(caller_agent_id: impl Into<String>) -> Self {
        Self {
            caller_agent_id: caller_agent_id.into(),
            delegation_depth: 0,
            originating_domain: String::new(),
            trusted_domains: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// AllowedDomains helpers
// ---------------------------------------------------------------------------
//
// Spec source of truth: AgentPin technical specification §4.11. This module
// re-implements the helpers locally rather than linking the AgentPin crate
// (see module-level docs for rationale). Update both projects in lockstep if
// the convention ever changes.

/// Returns `true` when `list` is an unrestricted allow-list (empty).
pub fn is_unrestricted(list: &[String]) -> bool {
    list.is_empty()
}

/// Returns `true` when `domain` is permitted under `list`.
///
/// An empty `list` allows everything. A non-empty `list` allows the domain
/// when it exactly matches an entry OR matches one of the entry's wildcard
/// patterns. Pattern matching follows AgentPin spec §5.5: a leading `*.`
/// matches any subdomain (e.g. `*.client.com` matches `api.client.com`
/// but not `client.com` itself).
pub fn allows(list: &[String], domain: &str) -> bool {
    if is_unrestricted(list) {
        return true;
    }
    list.iter().any(|pattern| pattern_matches(pattern, domain))
}

/// Intersection of two allow-lists, honouring the `empty = unrestricted`
/// convention.
///
/// - `unrestricted ∩ X = X`
/// - `X ∩ unrestricted = X`
/// - Otherwise: literal set intersection of `lhs` and `rhs` (string equality;
///   no wildcard expansion). Preserves the order of `lhs`.
///
/// An intersection that yields an empty `Vec` from two non-empty inputs is
/// *re-interpreted as unrestricted* under the same convention. This is the
/// AgentPin spec §4.11.4 edge case — callers needing to distinguish
/// "intentionally restricted to nothing" from "no restriction" must track
/// that distinction outside the allow-list value.
pub fn intersect(lhs: &[String], rhs: &[String]) -> Vec<String> {
    if is_unrestricted(lhs) {
        return rhs.to_vec();
    }
    if is_unrestricted(rhs) {
        return lhs.to_vec();
    }
    lhs.iter()
        .filter(|d| rhs.iter().any(|r| r == *d))
        .cloned()
        .collect()
}

/// Wildcard-aware domain pattern matcher.
///
/// `*.example.com` matches `api.example.com` and `a.b.example.com` but NOT
/// `example.com` itself. Anything without a leading `*.` is a literal
/// equality check.
fn pattern_matches(pattern: &str, domain: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // Match {anything}.suffix but not bare suffix.
        if domain.len() <= suffix.len() {
            return false;
        }
        let dot_position = domain.len() - suffix.len() - 1;
        return domain.ends_with(suffix) && domain.as_bytes().get(dot_position) == Some(&b'.');
    }
    pattern == domain
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrestricted_helpers_round_trip() {
        let ad: Vec<String> = Vec::new();
        assert!(is_unrestricted(&ad));
        assert!(allows(&ad, "anything.example.com"));
        assert!(allows(&ad, "literally-anything"));
    }

    #[test]
    fn restricted_allows_only_listed_domains() {
        let ad: Vec<String> = vec!["api.client.com".to_string(), "*.partner.com".to_string()];
        assert!(allows(&ad, "api.client.com"));
        assert!(allows(&ad, "tools.partner.com"));
        assert!(allows(&ad, "deep.nested.partner.com"));
        assert!(!allows(&ad, "partner.com")); // *.partner.com does not match bare partner.com
        assert!(!allows(&ad, "evil.example.com"));
    }

    #[test]
    fn intersect_with_unrestricted_returns_other() {
        let unrestricted: Vec<String> = Vec::new();
        let restricted = vec!["a.com".to_string(), "b.com".to_string()];
        assert_eq!(intersect(&unrestricted, &restricted), restricted);
        assert_eq!(intersect(&restricted, &unrestricted), restricted);
    }

    #[test]
    fn intersect_returns_overlap() {
        let lhs = vec![
            "a.com".to_string(),
            "b.com".to_string(),
            "c.com".to_string(),
        ];
        let rhs = vec![
            "b.com".to_string(),
            "c.com".to_string(),
            "d.com".to_string(),
        ];
        assert_eq!(
            intersect(&lhs, &rhs),
            vec!["b.com".to_string(), "c.com".to_string()]
        );
    }

    #[test]
    fn intersect_empty_overlap_is_treated_as_unrestricted() {
        let lhs = vec!["a.com".to_string()];
        let rhs = vec!["b.com".to_string()];
        let result = intersect(&lhs, &rhs);
        assert!(is_unrestricted(&result));
    }

    #[test]
    fn pattern_wildcard_does_not_match_bare_domain() {
        assert!(pattern_matches("*.partner.com", "api.partner.com"));
        assert!(!pattern_matches("*.partner.com", "partner.com"));
        assert!(!pattern_matches("*.partner.com", "partnercom"));
    }
}
