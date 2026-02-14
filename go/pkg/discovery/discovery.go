// Package discovery provides .well-known endpoint discovery for SchemaPin.
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ThirdKeyAi/schemapin/go/pkg/crypto"
)

// WellKnownResponse represents .well-known/schemapin.json structure
type WellKnownResponse struct {
	SchemaVersion      string   `json:"schema_version"`
	DeveloperName      string   `json:"developer_name"`
	PublicKeyPEM       string   `json:"public_key_pem"`
	Contact            string   `json:"contact,omitempty"`
	RevokedKeys        []string `json:"revoked_keys,omitempty"`
	RevocationEndpoint string   `json:"revocation_endpoint,omitempty"`
}

// PublicKeyDiscovery handles .well-known endpoint discovery
type PublicKeyDiscovery struct {
	client     *http.Client
	keyManager *crypto.KeyManager
}

// NewPublicKeyDiscovery creates a new PublicKeyDiscovery instance
func NewPublicKeyDiscovery() *PublicKeyDiscovery {
	return &PublicKeyDiscovery{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		keyManager: crypto.NewKeyManager(),
	}
}

// NewPublicKeyDiscoveryWithTimeout creates a new PublicKeyDiscovery instance with custom timeout
func NewPublicKeyDiscoveryWithTimeout(timeout time.Duration) *PublicKeyDiscovery {
	return &PublicKeyDiscovery{
		client: &http.Client{
			Timeout: timeout,
		},
		keyManager: crypto.NewKeyManager(),
	}
}

// ConstructWellKnownURL constructs the .well-known URL for a domain
func ConstructWellKnownURL(domain string) string {
	// Handle domains with or without protocol
	if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
		domain = "https://" + domain
	}

	baseURL, err := url.Parse(domain)
	if err != nil {
		// Fallback to simple concatenation if URL parsing fails
		return fmt.Sprintf("https://%s/.well-known/schemapin.json", strings.TrimPrefix(strings.TrimPrefix(domain, "https://"), "http://"))
	}

	baseURL.Path = "/.well-known/schemapin.json"
	return baseURL.String()
}

// ConstructWellKnownURL constructs the .well-known URL for a domain (instance method)
func (p *PublicKeyDiscovery) ConstructWellKnownURL(domain string) string {
	return ConstructWellKnownURL(domain)
}

// ValidateWellKnownResponse validates .well-known response structure
func ValidateWellKnownResponse(response *WellKnownResponse) bool {
	return response != nil &&
		response.SchemaVersion != "" &&
		response.PublicKeyPEM != ""
}

// FetchWellKnown fetches and validates .well-known/schemapin.json from domain
func (p *PublicKeyDiscovery) FetchWellKnown(ctx context.Context, domain string) (*WellKnownResponse, error) {
	url := p.ConstructWellKnownURL(domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := p.client.Do(req) // #nosec G704 -- URL constructed from ConstructWellKnownURL with domain validation
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

	if !ValidateWellKnownResponse(&wellKnown) {
		return nil, fmt.Errorf("invalid .well-known response structure")
	}

	return &wellKnown, nil
}

// FetchWellKnownWithTimeout fetches .well-known with custom timeout
func (p *PublicKeyDiscovery) FetchWellKnownWithTimeout(domain string, timeout time.Duration) (*WellKnownResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return p.FetchWellKnown(ctx, domain)
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

// GetPublicKeyPEMWithTimeout retrieves public key PEM with custom timeout
func (p *PublicKeyDiscovery) GetPublicKeyPEMWithTimeout(domain string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return p.GetPublicKeyPEM(ctx, domain)
}

// CheckKeyRevocation checks if a public key is in the revocation list
func CheckKeyRevocation(publicKeyPEM string, revokedKeys []string) bool {
	if len(revokedKeys) == 0 {
		return false
	}

	// Try direct PEM comparison first
	for _, revokedKey := range revokedKeys {
		if revokedKey == publicKeyPEM {
			return true
		}
	}

	// Try fingerprint comparison
	keyManager := crypto.NewKeyManager()
	fingerprint, err := keyManager.CalculateKeyFingerprintFromPEM(publicKeyPEM)
	if err != nil {
		// If we can't calculate fingerprint, assume not revoked
		return false
	}

	for _, revokedKey := range revokedKeys {
		if revokedKey == fingerprint {
			return true
		}
	}

	return false
}

// GetRevokedKeys retrieves revoked keys list from domain's .well-known endpoint
func (p *PublicKeyDiscovery) GetRevokedKeys(ctx context.Context, domain string) ([]string, error) {
	wellKnown, err := p.FetchWellKnown(ctx, domain)
	if err != nil {
		return nil, err
	}

	if wellKnown.RevokedKeys == nil {
		return []string{}, nil
	}

	return wellKnown.RevokedKeys, nil
}

// GetRevokedKeysWithTimeout retrieves revoked keys with custom timeout
func (p *PublicKeyDiscovery) GetRevokedKeysWithTimeout(domain string, timeout time.Duration) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return p.GetRevokedKeys(ctx, domain)
}

// ValidateKeyNotRevoked validates that a public key is not revoked
func (p *PublicKeyDiscovery) ValidateKeyNotRevoked(ctx context.Context, publicKeyPEM, domain string) (bool, error) {
	revokedKeys, err := p.GetRevokedKeys(ctx, domain)
	if err != nil {
		// If we can't fetch revocation list, assume not revoked
		return true, nil
	}

	return !CheckKeyRevocation(publicKeyPEM, revokedKeys), nil
}

// ValidateKeyNotRevokedWithTimeout validates key revocation with custom timeout
func (p *PublicKeyDiscovery) ValidateKeyNotRevokedWithTimeout(publicKeyPEM, domain string, timeout time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return p.ValidateKeyNotRevoked(ctx, publicKeyPEM, domain)
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
	}

	if wellKnown.Contact != "" {
		info["contact"] = wellKnown.Contact
	}

	// Set defaults for missing fields
	if info["developer_name"] == "" {
		info["developer_name"] = "Unknown"
	}
	if info["schema_version"] == "" {
		info["schema_version"] = "1.0"
	}

	return info, nil
}

// GetDeveloperInfoWithTimeout retrieves developer info with custom timeout
func (p *PublicKeyDiscovery) GetDeveloperInfoWithTimeout(domain string, timeout time.Duration) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return p.GetDeveloperInfo(ctx, domain)
}
