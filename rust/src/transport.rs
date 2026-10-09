//! Hardened HTTP fetch helper shared by discovery and revocation (`fetch`
//! feature).
//!
//! Every outbound request made by this crate goes through [`fetch_json`]:
//!
//! - `https://` only -- plaintext URLs are refused before any socket is opened
//! - redirects are never followed
//! - the response body is capped at [`MAX_RESPONSE_BYTES`]
//! - connect and total timeouts are always applied

use crate::error::Error;

/// Maximum accepted response body size (bytes).
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Default total request timeout (seconds).
pub const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// Return `Ok(())` if `url` is an absolute `https://` URL without userinfo.
pub fn require_https(url: &str) -> Result<(), Error> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| Error::Transport(format!("only https:// URLs are permitted: {:?}", url)))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return Err(Error::Transport(format!("invalid URL: {:?}", url)));
    }
    if authority.contains('@') {
        return Err(Error::Transport(format!(
            "userinfo is not permitted in URLs: {:?}",
            url
        )));
    }
    Ok(())
}

/// Build a `reqwest::Client` with the hardening rules applied.
#[cfg(feature = "fetch")]
pub fn hardened_client() -> Result<reqwest::Client, Error> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .connect_timeout(std::time::Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .user_agent("SchemaPin")
        .build()
        .map_err(|e| Error::Transport(e.to_string()))
}

/// GET `url` and decode the JSON body under the hardening rules above.
#[cfg(feature = "fetch")]
pub async fn fetch_json<T: serde::de::DeserializeOwned>(url: &str) -> Result<T, Error> {
    require_https(url)?;
    let client = hardened_client()?;
    let mut resp = client
        .get(url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| Error::Transport(format!("request failed for {}: {}", url, e)))?;

    if resp.status().is_redirection() {
        return Err(Error::Transport(format!(
            "redirect ({}) fetching {}; redirects are not followed",
            resp.status(),
            url
        )));
    }
    if resp.status() != reqwest::StatusCode::OK {
        return Err(Error::Transport(format!(
            "HTTP {} fetching {}",
            resp.status(),
            url
        )));
    }
    if let Some(len) = resp.content_length() {
        if len as usize > MAX_RESPONSE_BYTES {
            return Err(Error::Transport(format!(
                "response from {} exceeds {} bytes",
                url, MAX_RESPONSE_BYTES
            )));
        }
    }
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| Error::Transport(format!("reading {}: {}", url, e)))?
    {
        body.extend_from_slice(&chunk);
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(Error::Transport(format!(
                "response from {} exceeds {} bytes",
                url, MAX_RESPONSE_BYTES
            )));
        }
    }
    serde_json::from_slice(&body)
        .map_err(|e| Error::Transport(format!("invalid JSON from {}: {}", url, e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_required() {
        for bad in [
            "http://example.com/x",
            "ftp://example.com/x",
            "https://user:pw@example.com/x",
            "example.com",
            "https://",
            "",
        ] {
            assert!(require_https(bad).is_err(), "{:?} must be rejected", bad);
        }
        assert!(require_https("https://example.com/.well-known/schemapin.json").is_ok());
    }
}
