// Package discovery provides .well-known endpoint discovery for SchemaPin.
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// WellKnownResponse represents .well-known/schemapin.json structure
type WellKnownResponse struct {
	SchemaVersion string   `json:"schema_version"`
	DeveloperName string   `json:"developer_name"`
	PublicKeyPEM  string   `json:"public_key_pem"`
	Contact       string   `json:"contact,omitempty"`
	RevokedKeys   []string `json:"revoked_keys,omitempty"`
}

// PublicKeyDiscovery handles .well-known endpoint discovery
type PublicKeyDiscovery struct {
	client *http.Client
}

// NewPublicKeyDiscovery creates a new PublicKeyDiscovery instance
func NewPublicKeyDiscovery() *PublicKeyDiscovery {
	return &PublicKeyDiscovery{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ConstructWellKnownURL constructs the .well-known URL for a domain
func (p *PublicKeyDiscovery) ConstructWellKnownURL(domain string) string {
	return fmt.Sprintf("https://%s/.well-known/schemapin.json", domain)
}

// FetchWellKnown fetches and parses the .well-known/schemapin.json file
func (p *PublicKeyDiscovery) FetchWellKnown(ctx context.Context, domain string) (*WellKnownResponse, error) {
	url := p.ConstructWellKnownURL(domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch .well-known file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var wellKnown WellKnownResponse
	if err := json.NewDecoder(resp.Body).Decode(&wellKnown); err != nil {
		return nil, fmt.Errorf("failed to decode .well-known response: %w", err)
	}

	return &wellKnown, nil
}

// GetPublicKeyPEM retrieves the public key PEM from .well-known endpoint
func (p *PublicKeyDiscovery) GetPublicKeyPEM(ctx context.Context, domain string) (string, error) {
	wellKnown, err := p.FetchWellKnown(ctx, domain)
	if err != nil {
		return "", err
	}

	if wellKnown.PublicKeyPEM == "" {
		return "", fmt.Errorf("no public key found in .well-known response")
	}

	return wellKnown.PublicKeyPEM, nil
}

// ValidateKeyNotRevoked checks if a public key is not in the revoked keys list
func (p *PublicKeyDiscovery) ValidateKeyNotRevoked(ctx context.Context, publicKeyPEM, domain string) (bool, error) {
	wellKnown, err := p.FetchWellKnown(ctx, domain)
	if err != nil {
		return false, err
	}

	// Check if the key is in the revoked list
	for _, revokedKey := range wellKnown.RevokedKeys {
		if revokedKey == publicKeyPEM {
			return false, nil
		}
	}

	return true, nil
}

// GetDeveloperInfo retrieves developer information from .well-known endpoint
func (p *PublicKeyDiscovery) GetDeveloperInfo(ctx context.Context, domain string) (map[string]string, error) {
	wellKnown, err := p.FetchWellKnown(ctx, domain)
	if err != nil {
		return nil, err
	}

	info := map[string]string{
		"developer_name": wellKnown.DeveloperName,
		"schema_version": wellKnown.SchemaVersion,
		"domain":         domain,
	}

	if wellKnown.Contact != "" {
		info["contact"] = wellKnown.Contact
	}

	return info, nil
}
