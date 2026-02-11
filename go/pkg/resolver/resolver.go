// Package resolver provides a discovery resolver abstraction for SchemaPin.
package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ThirdKeyAi/schemapin/go/pkg/bundle"
	"github.com/ThirdKeyAi/schemapin/go/pkg/discovery"
	"github.com/ThirdKeyAi/schemapin/go/pkg/revocation"
)

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
func (r *LocalFileResolver) ResolveDiscovery(domain string) (*discovery.WellKnownResponse, error) {
	path := filepath.Join(r.discoveryDir, domain+".json")
	data, err := os.ReadFile(path)
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
func (r *LocalFileResolver) ResolveRevocation(domain string, disc *discovery.WellKnownResponse) (*revocation.RevocationDocument, error) {
	if r.revocationDir == "" {
		return nil, nil
	}

	path := filepath.Join(r.revocationDir, domain+".revocations.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil // Missing file is not an error
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

// ResolveRevocation tries each resolver in order.
func (r *ChainResolver) ResolveRevocation(domain string, disc *discovery.WellKnownResponse) (*revocation.RevocationDocument, error) {
	for _, resolver := range r.resolvers {
		doc, err := resolver.ResolveRevocation(domain, disc)
		if err == nil && doc != nil {
			return doc, nil
		}
	}
	return nil, nil
}
