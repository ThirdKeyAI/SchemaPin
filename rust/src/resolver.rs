//! Discovery resolver abstraction.
//!
//! Provides pluggable discovery mechanisms beyond the standard
//! `https://{domain}/.well-known/schemapin.json` endpoint.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::Error;
use crate::types::bundle::SchemaPinTrustBundle;
use crate::types::discovery::WellKnownResponse;
use crate::types::revocation::RevocationDocument;

// ---------------------------------------------------------------------------
// Sync resolver trait (always available)
// ---------------------------------------------------------------------------

/// Resolve discovery and revocation documents for a given domain.
///
/// Implementations can fetch from `.well-known` URLs, the local filesystem,
/// an in-memory trust bundle, or any other source.
pub trait SchemaResolver: Send + Sync {
    /// Return the well-known response for `domain`.
    fn resolve_discovery(&self, domain: &str) -> Result<WellKnownResponse, Error>;

    /// Return the revocation document for `domain`, if available.
    ///
    /// The default implementation returns `Ok(None)`.
    fn resolve_revocation(
        &self,
        domain: &str,
        _discovery: &WellKnownResponse,
    ) -> Result<Option<RevocationDocument>, Error> {
        let _ = domain;
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Async resolver trait (fetch-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "fetch")]
/// Async equivalent of [`SchemaResolver`].
///
/// Gated behind the `fetch` feature because it brings in `async-trait`.
#[async_trait::async_trait]
pub trait AsyncSchemaResolver: Send + Sync {
    async fn resolve_discovery(&self, domain: &str) -> Result<WellKnownResponse, Error>;

    async fn resolve_revocation(
        &self,
        domain: &str,
        _discovery: &WellKnownResponse,
    ) -> Result<Option<RevocationDocument>, Error> {
        let _ = domain;
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// WellKnownResolver (fetch-gated — wraps existing HTTP fetchers)
// ---------------------------------------------------------------------------

#[cfg(feature = "fetch")]
/// Fetches documents from the standard `.well-known` HTTPS endpoint.
pub struct WellKnownResolver;

#[cfg(feature = "fetch")]
#[async_trait::async_trait]
impl AsyncSchemaResolver for WellKnownResolver {
    async fn resolve_discovery(&self, domain: &str) -> Result<WellKnownResponse, Error> {
        crate::discovery::fetch_well_known(domain).await
    }

    async fn resolve_revocation(
        &self,
        _domain: &str,
        discovery: &WellKnownResponse,
    ) -> Result<Option<RevocationDocument>, Error> {
        if let Some(ref endpoint) = discovery.revocation_endpoint {
            let doc = crate::revocation::fetch_revocation_document(endpoint).await?;
            Ok(Some(doc))
        } else {
            Ok(None)
        }
    }
}

// ---------------------------------------------------------------------------
// LocalFileResolver (sync — reads from filesystem)
// ---------------------------------------------------------------------------

/// Reads discovery documents from a local directory.
///
/// Expects files named `{domain}.json` under `discovery_dir`. Optionally
/// reads revocation documents from `{domain}.revocations.json` in the same
/// directory (or a separate `revocation_dir`).
pub struct LocalFileResolver {
    discovery_dir: PathBuf,
    revocation_dir: Option<PathBuf>,
}

impl LocalFileResolver {
    pub fn new(discovery_dir: &Path, revocation_dir: Option<&Path>) -> Self {
        Self {
            discovery_dir: discovery_dir.to_path_buf(),
            revocation_dir: revocation_dir.map(|p| p.to_path_buf()),
        }
    }
}

impl SchemaResolver for LocalFileResolver {
    fn resolve_discovery(&self, domain: &str) -> Result<WellKnownResponse, Error> {
        let path = self.discovery_dir.join(format!("{}.json", domain));
        let data = std::fs::read_to_string(&path)
            .map_err(|e| Error::Discovery(format!("Cannot read {}: {}", path.display(), e)))?;
        let doc: WellKnownResponse = serde_json::from_str(&data)?;
        Ok(doc)
    }

    fn resolve_revocation(
        &self,
        domain: &str,
        _discovery: &WellKnownResponse,
    ) -> Result<Option<RevocationDocument>, Error> {
        let dir = self.revocation_dir.as_ref().unwrap_or(&self.discovery_dir);
        let path = dir.join(format!("{}.revocations.json", domain));
        if !path.exists() {
            return Ok(None);
        }
        let data = std::fs::read_to_string(&path)
            .map_err(|e| Error::Discovery(format!("Cannot read {}: {}", path.display(), e)))?;
        let doc: RevocationDocument = serde_json::from_str(&data)?;
        Ok(Some(doc))
    }
}

// ---------------------------------------------------------------------------
// TrustBundleResolver (sync — in-memory lookup)
// ---------------------------------------------------------------------------

/// Resolves documents from a pre-loaded [`SchemaPinTrustBundle`].
pub struct TrustBundleResolver {
    discovery: HashMap<String, WellKnownResponse>,
    revocations: HashMap<String, RevocationDocument>,
}

impl TrustBundleResolver {
    /// Build from a [`SchemaPinTrustBundle`].
    pub fn new(bundle: &SchemaPinTrustBundle) -> Self {
        let mut discovery = HashMap::new();
        for doc in &bundle.documents {
            discovery.insert(doc.domain.clone(), doc.well_known.clone());
        }
        let mut revocations = HashMap::new();
        for doc in &bundle.revocations {
            revocations.insert(doc.domain.clone(), doc.clone());
        }
        Self {
            discovery,
            revocations,
        }
    }

    /// Build from a JSON string representing a [`SchemaPinTrustBundle`].
    pub fn from_json(json: &str) -> Result<Self, Error> {
        let bundle: SchemaPinTrustBundle = serde_json::from_str(json)?;
        Ok(Self::new(&bundle))
    }
}

impl SchemaResolver for TrustBundleResolver {
    fn resolve_discovery(&self, domain: &str) -> Result<WellKnownResponse, Error> {
        self.discovery
            .get(domain)
            .cloned()
            .ok_or_else(|| Error::Discovery(format!("Domain '{}' not in trust bundle", domain)))
    }

    fn resolve_revocation(
        &self,
        domain: &str,
        _discovery: &WellKnownResponse,
    ) -> Result<Option<RevocationDocument>, Error> {
        Ok(self.revocations.get(domain).cloned())
    }
}

// ---------------------------------------------------------------------------
// ChainResolver (sync — tries resolvers in order)
// ---------------------------------------------------------------------------

/// Composite resolver that tries a sequence of resolvers in order until one
/// succeeds.
pub struct ChainResolver {
    resolvers: Vec<Box<dyn SchemaResolver>>,
}

impl ChainResolver {
    pub fn new(resolvers: Vec<Box<dyn SchemaResolver>>) -> Self {
        Self { resolvers }
    }
}

impl SchemaResolver for ChainResolver {
    fn resolve_discovery(&self, domain: &str) -> Result<WellKnownResponse, Error> {
        let mut last_err = Error::Discovery("No resolvers configured".to_string());
        for resolver in &self.resolvers {
            match resolver.resolve_discovery(domain) {
                Ok(doc) => return Ok(doc),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    fn resolve_revocation(
        &self,
        domain: &str,
        discovery: &WellKnownResponse,
    ) -> Result<Option<RevocationDocument>, Error> {
        for resolver in &self.resolvers {
            match resolver.resolve_revocation(domain, discovery) {
                Ok(Some(doc)) => return Ok(Some(doc)),
                Ok(None) => continue,
                Err(_) => continue,
            }
        }
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::build_well_known_response;
    use crate::revocation::build_revocation_document;
    use crate::types::bundle::BundledDiscovery;

    fn make_well_known(pem: &str) -> WellKnownResponse {
        build_well_known_response(pem, Some("Test"), vec![], "1.2")
    }

    fn make_bundle(domain: &str) -> SchemaPinTrustBundle {
        SchemaPinTrustBundle {
            schemapin_bundle_version: "1.2".to_string(),
            created_at: "2026-02-10T00:00:00Z".to_string(),
            documents: vec![BundledDiscovery {
                domain: domain.to_string(),
                well_known: make_well_known(
                    "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
                ),
            }],
            revocations: vec![],
        }
    }

    // -- TrustBundleResolver -------------------------------------------------

    #[test]
    fn test_trust_bundle_resolver_hit() {
        let bundle = make_bundle("example.com");
        let resolver = TrustBundleResolver::new(&bundle);
        let doc = resolver.resolve_discovery("example.com").unwrap();
        assert_eq!(doc.schema_version, "1.2");
    }

    #[test]
    fn test_trust_bundle_resolver_miss() {
        let bundle = SchemaPinTrustBundle::new("2026-02-10T00:00:00Z");
        let resolver = TrustBundleResolver::new(&bundle);
        assert!(resolver.resolve_discovery("missing.com").is_err());
    }

    #[test]
    fn test_trust_bundle_resolver_revocation() {
        let rev = build_revocation_document("example.com");
        let mut bundle = make_bundle("example.com");
        bundle.revocations = vec![rev];
        let resolver = TrustBundleResolver::new(&bundle);
        let disc = resolver.resolve_discovery("example.com").unwrap();
        let rev = resolver.resolve_revocation("example.com", &disc).unwrap();
        assert!(rev.is_some());
    }

    #[test]
    fn test_trust_bundle_resolver_from_json() {
        let bundle = make_bundle("example.com");
        let json = serde_json::to_string(&bundle).unwrap();
        let resolver = TrustBundleResolver::from_json(&json).unwrap();
        assert!(resolver.resolve_discovery("example.com").is_ok());
    }

    // -- LocalFileResolver ---------------------------------------------------

    #[test]
    fn test_local_file_resolver() {
        let dir = tempfile::tempdir().unwrap();
        let wk = make_well_known("-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----");
        let path = dir.path().join("local.example.com.json");
        std::fs::write(&path, serde_json::to_string_pretty(&wk).unwrap()).unwrap();

        let resolver = LocalFileResolver::new(dir.path(), None);
        let resolved = resolver.resolve_discovery("local.example.com").unwrap();
        assert_eq!(resolved.schema_version, "1.2");
    }

    #[test]
    fn test_local_file_resolver_missing() {
        let dir = tempfile::tempdir().unwrap();
        let resolver = LocalFileResolver::new(dir.path(), None);
        assert!(resolver.resolve_discovery("missing.com").is_err());
    }

    #[test]
    fn test_local_file_resolver_revocation() {
        let dir = tempfile::tempdir().unwrap();
        let wk = make_well_known("-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----");
        let rev = build_revocation_document("local.example.com");
        std::fs::write(
            dir.path().join("local.example.com.json"),
            serde_json::to_string(&wk).unwrap(),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("local.example.com.revocations.json"),
            serde_json::to_string(&rev).unwrap(),
        )
        .unwrap();

        let resolver = LocalFileResolver::new(dir.path(), None);
        let resolved = resolver
            .resolve_revocation("local.example.com", &wk)
            .unwrap();
        assert!(resolved.is_some());
    }

    // -- ChainResolver -------------------------------------------------------

    #[test]
    fn test_chain_resolver_first_wins() {
        let bundle_a = make_bundle("a.com");
        let bundle_b = make_bundle("b.com");

        let chain = ChainResolver::new(vec![
            Box::new(TrustBundleResolver::new(&bundle_a)),
            Box::new(TrustBundleResolver::new(&bundle_b)),
        ]);

        assert!(chain.resolve_discovery("a.com").is_ok());
        assert!(chain.resolve_discovery("b.com").is_ok());
        assert!(chain.resolve_discovery("c.com").is_err());
    }

    #[test]
    fn test_chain_resolver_fallthrough() {
        let empty = SchemaPinTrustBundle::new("2026-02-10T00:00:00Z");
        let has_doc = make_bundle("example.com");

        let chain = ChainResolver::new(vec![
            Box::new(TrustBundleResolver::new(&empty)),
            Box::new(TrustBundleResolver::new(&has_doc)),
        ]);

        let doc = chain.resolve_discovery("example.com").unwrap();
        assert_eq!(doc.schema_version, "1.2");
    }
}
