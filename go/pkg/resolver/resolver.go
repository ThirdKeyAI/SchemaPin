// Package resolver provides a discovery resolver abstraction for SchemaPin.
package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ThirdKeyAi/schemapin/go/pkg/bundle"
	"github.com/ThirdKeyAi/schemapin/go/pkg/discovery"
	"github.com/ThirdKeyAi/schemapin/go/pkg/domain"
	"github.com/ThirdKeyAi/schemapin/go/pkg/revocation"
)

// safeDomainPath joins a validated domain-derived file name onto baseDir and
// makes sure the result stays inside baseDir (SP-16).
func safeDomainPath(baseDir, domainName, suffix string) (string, error) {
	normalized, err := domain.ValidateDomain(domainName)
	if err != nil {
		return "", err
	}
	root, err := filepath.Abs(baseDir)
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, normalized+suffix)
	if path != root && !strings.HasPrefix(path, root+string(filepath.Separator)) {
		return "", fmt.Errorf("resolved path %s escapes %s", path, root)
	}
	return path, nil
}

// SchemaResolver is the interface for resolving discovery and revocation documents.
type SchemaResolver interface {
	ResolveDiscovery(domain string) (*discovery.WellKnownResponse, error)
	ResolveRevocation(domain string, disc *discovery.WellKnownResponse) (*revocation.RevocationDocument, error)
}

// WellKnownResolver resolves discovery via standard .well-known HTTPS endpoints.
type WellKnownResolver struct {
	discovery *discovery.PublicKeyDiscovery
}

// NewWellKnownResolver creates a new WellKnownResolver.
func NewWellKnownResolver() *WellKnownResolver {
	return &WellKnownResolver{
		discovery: discovery.NewPublicKeyDiscovery(),
	}
}

// ResolveDiscovery fetches discovery from the .well-known endpoint.
func (r *WellKnownResolver) ResolveDiscovery(domain string) (*discovery.WellKnownResponse, error) {
	return r.discovery.FetchWellKnown(context.Background(), domain)
}

// ResolveRevocation fetches revocation from the discovery's revocation_endpoint.
// A declared endpoint that cannot be fetched is an error (callers fail closed).
func (r *WellKnownResolver) ResolveRevocation(domain string, disc *discovery.WellKnownResponse) (*revocation.RevocationDocument, error) {
	if disc == nil || disc.RevocationEndpoint == "" {
		return nil, nil
	}
	doc, err := revocation.FetchRevocationDocument(context.Background(), disc.RevocationEndpoint)
	if err != nil {
		return nil, err
	}
	return doc, nil
}

// LocalFileResolver resolves discovery from local JSON files.
//
// The domain is validated and the resolved path must stay inside the
// configured directory, so a hostile domain string cannot select an
// arbitrary file.
type LocalFileResolver struct {
	discoveryDir  string
	revocationDir string
}

// NewLocalFileResolver creates a new LocalFileResolver.
func NewLocalFileResolver(discoveryDir, revocationDir string) *LocalFileResolver {
	return &LocalFileResolver{
		discoveryDir:  discoveryDir,
		revocationDir: revocationDir,
	}
}

// ResolveDiscovery reads {domain}.json from the discovery directory.
func (r *LocalFileResolver) ResolveDiscovery(domainName string) (*discovery.WellKnownResponse, error) {
	path, err := safeDomainPath(r.discoveryDir, domainName, ".json")
	if err != nil {
		return nil, fmt.Errorf("invalid domain for local discovery: %w", err)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- domain validated and path confined by safeDomainPath
	if err != nil {
		return nil, fmt.Errorf("failed to read discovery file: %w", err)
	}

	var resp discovery.WellKnownResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse discovery file: %w", err)
	}

	return &resp, nil
}

// ResolveRevocation reads {domain}.revocations.json from the revocation directory.
func (r *LocalFileResolver) ResolveRevocation(domainName string, disc *discovery.WellKnownResponse) (*revocation.RevocationDocument, error) {
	if r.revocationDir == "" {
		return nil, nil
	}

	path, err := safeDomainPath(r.revocationDir, domainName, ".revocations.json")
	if err != nil {
		return nil, fmt.Errorf("invalid domain for local revocation: %w", err)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- domain validated and path confined by safeDomainPath
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // Missing file is not an error
		}
		return nil, fmt.Errorf("failed to read revocation file: %w", err)
	}

	var doc revocation.RevocationDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse revocation file: %w", err)
	}

	return &doc, nil
}

// TrustBundleResolver resolves discovery from an in-memory trust bundle.
type TrustBundleResolver struct {
	bundle *bundle.SchemaPinTrustBundle
}

// NewTrustBundleResolver creates a new TrustBundleResolver.
func NewTrustBundleResolver(b *bundle.SchemaPinTrustBundle) *TrustBundleResolver {
	return &TrustBundleResolver{bundle: b}
}

// FromJSON creates a TrustBundleResolver from a JSON string.
func FromJSON(jsonStr string) (*TrustBundleResolver, error) {
	b, err := bundle.ParseTrustBundle(jsonStr)
	if err != nil {
		return nil, err
	}
	return NewTrustBundleResolver(b), nil
}

// ResolveDiscovery looks up discovery in the bundle.
func (r *TrustBundleResolver) ResolveDiscovery(domain string) (*discovery.WellKnownResponse, error) {
	disc := r.bundle.FindDiscovery(domain)
	if disc == nil {
		return nil, fmt.Errorf("domain %s not found in trust bundle", domain)
	}
	return disc, nil
}

// ResolveRevocation looks up revocation in the bundle.
func (r *TrustBundleResolver) ResolveRevocation(domain string, disc *discovery.WellKnownResponse) (*revocation.RevocationDocument, error) {
	return r.bundle.FindRevocation(domain), nil
}

// ChainResolver tries multiple resolvers in order, returning the first success.
//
// Precedence is positional: put the most trusted source first. A revocation
// fetch failure from any member propagates (fail-closed) instead of being
// skipped.
type ChainResolver struct {
	resolvers []SchemaResolver
}

// NewChainResolver creates a new ChainResolver.
func NewChainResolver(resolvers []SchemaResolver) *ChainResolver {
	return &ChainResolver{resolvers: resolvers}
}

// ResolveDiscovery tries each resolver in order.
func (r *ChainResolver) ResolveDiscovery(domain string) (*discovery.WellKnownResponse, error) {
	var lastErr error
	for _, resolver := range r.resolvers {
		disc, err := resolver.ResolveDiscovery(domain)
		if err == nil {
			return disc, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no resolvers available")
}

// ResolveRevocation tries each resolver in order. The first error is returned
// rather than skipped: a declared-but-unreachable revocation source must not
// silently degrade to "not revoked".
func (r *ChainResolver) ResolveRevocation(domain string, disc *discovery.WellKnownResponse) (*revocation.RevocationDocument, error) {
	for _, resolver := range r.resolvers {
		doc, err := resolver.ResolveRevocation(domain, disc)
		if err != nil {
			return nil, err
		}
		if doc != nil {
			return doc, nil
		}
	}
	return nil, nil
}
