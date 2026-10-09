//! Shared domain-name validation.
//!
//! Every place that turns a domain string into something security-relevant --
//! a `.well-known` URL, a pin-store key, a local file path, a DNS lookup name
//! -- MUST pass it through [`validate_domain`] first. The grammar is the
//! RFC 1123 hostname grammar, restricted further so the value cannot be
//! confused with a URL, a path, an IP literal or an IDN U-label:
//!
//! - ASCII only (internationalized names must be given as punycode A-labels)
//! - at least two labels, each 1-63 characters of `[a-z0-9-]` that neither
//!   start nor end with `-`
//! - total length at most 253 characters
//! - the last label is not purely numeric (rejects IPv4 literals)
//! - no scheme, path, port, userinfo or trailing dot
//!
//! The returned value is lowercased so pin keys and file names are consistent
//! regardless of how the caller spelled the domain.

use crate::error::Error;

/// Maximum total length of a domain name.
pub const MAX_DOMAIN_LENGTH: usize = 253;

fn invalid(msg: String) -> Error {
    Error::InvalidDomain(msg)
}

fn valid_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }
    if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

/// Validate `domain` and return its normalized (lowercase) form.
pub fn validate_domain(domain: &str) -> Result<String, Error> {
    if domain.is_empty() {
        return Err(invalid("domain must be a non-empty string".to_string()));
    }
    if domain.len() > MAX_DOMAIN_LENGTH {
        return Err(invalid(format!(
            "domain exceeds {} characters",
            MAX_DOMAIN_LENGTH
        )));
    }
    if !domain.is_ascii() {
        return Err(invalid(
            "domain must be ASCII; encode internationalized names as punycode".to_string(),
        ));
    }
    let normalized = domain.to_ascii_lowercase();
    let labels: Vec<&str> = normalized.split('.').collect();
    if labels.len() < 2 {
        return Err(invalid(format!(
            "domain {:?} must contain at least two labels",
            domain
        )));
    }
    for label in &labels {
        if !valid_label(label) {
            return Err(invalid(format!(
                "domain {:?} has an invalid label {:?}",
                domain, label
            )));
        }
    }
    if labels[labels.len() - 1].bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid(format!(
            "domain {:?} looks like an IP literal",
            domain
        )));
    }
    Ok(normalized)
}

/// Returns `true` when [`validate_domain`] would accept `domain`.
pub fn is_valid_domain(domain: &str) -> bool {
    validate_domain(domain).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_domains() {
        for (input, want) in [
            ("example.com", "example.com"),
            ("Example.COM", "example.com"),
            ("sub.domain.example.co.uk", "sub.domain.example.co.uk"),
            ("xn--bcher-kva.example", "xn--bcher-kva.example"),
            ("a-b.c1", "a-b.c1"),
            ("1.example", "1.example"),
        ] {
            assert_eq!(validate_domain(input).unwrap(), want);
            assert!(is_valid_domain(input));
        }
    }

    #[test]
    fn rejects_invalid_domains() {
        let long_label = format!("{}.example.com", "a".repeat(64));
        let too_long = format!("{}com", format!("{}.", "a".repeat(63)).repeat(4));
        let bad = [
            "",
            "localhost",
            "example",
            "http://example.com",
            "https://example.com",
            "example.com/path",
            "example.com:8443",
            "user@example.com",
            "good.com@evil.com",
            "../skills/evil/key",
            "/etc/passwd",
            "example.com.",
            ".example.com",
            "exa mple.com",
            "-bad.example.com",
            "bad-.example.com",
            "under_score.example.com",
            "10.0.0.1",
            "[::1]",
            "bücher.example",
            long_label.as_str(),
            too_long.as_str(),
            "evil.com\nexample.com",
        ];
        for input in bad {
            assert!(
                matches!(validate_domain(input), Err(Error::InvalidDomain(_))),
                "{:?} must be rejected",
                input
            );
            assert!(!is_valid_domain(input));
        }
    }
}
