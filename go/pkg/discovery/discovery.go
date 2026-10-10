// Package discovery provides .well-known endpoint discovery for SchemaPin.
package discovery

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ThirdKeyAi/schemapin/go/pkg/crypto"
	"github.com/ThirdKeyAi/schemapin/go/pkg/domain"
	"github.com/ThirdKeyAi/schemapin/go/pkg/revocation"
	"github.com/ThirdKeyAi/schemapin/go/pkg/transport"
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

// NewPublicKeyDiscovery creates a new PublicKeyDiscovery instance. The HTTP
// client refuses redirects, caps response bodies and applies a 10s timeout.
func NewPublicKeyDiscovery() *PublicKeyDiscovery {
	return NewPublicKeyDiscoveryWithTimeout(transport.DefaultTimeout)
}

// NewPublicKeyDiscoveryWithTimeout creates a new PublicKeyDiscovery instance with custom timeout
func NewPublicKeyDiscoveryWithTimeout(timeout time.Duration) *PublicKeyDiscovery {
	return NewPublicKeyDiscoveryWithClient(transport.NewClient(timeout))
}

// NewPublicKeyDiscoveryWithClient creates a PublicKeyDiscovery that issues
// requests through client. The URL policy (https only, validated domain,
// capped body) still applies; the client is responsible for its own timeout
// and redirect policy (use transport.NewClient for the hardened defaults).
func NewPublicKeyDiscoveryWithClient(client *http.Client) *PublicKeyDiscovery {
	if client == nil {
		client = transport.NewClient(transport.DefaultTimeout)
	}
	return &PublicKeyDiscovery{
		client:     client,
		keyManager: crypto.NewKeyManager(),
	}
}

// ConstructWellKnownURL constructs the .well-known URL for a domain.
//
// The domain must be a bare hostname (an https:// prefix is tolerated and
// stripped). http:// is refused: the spec requires HTTPS and a plaintext
// first fetch would let a network attacker pin their own key.
func ConstructWellKnownURL(domainName string) (string, error) {
	if strings.HasPrefix(domainName, "http://") {
		return "", fmt.Errorf("%w: SchemaPin discovery requires https; http:// is not permitted", domain.ErrInvalidDomain)
	}
	domainName = strings.TrimRight(strings.TrimPrefix(domainName, "https://"), "/")
	normalized, err := domain.ValidateDomain(domainName)
	if err != nil {
		return "", err
	}
	return "https://" + normalized + "/.well-known/schemapin.json", nil
}

// ConstructWellKnownURL constructs the .well-known URL for a domain (instance method)
func (p *PublicKeyDiscovery) ConstructWellKnownURL(domainName string) (string, error) {
	return ConstructWellKnownURL(domainName)
}

// ValidateWellKnownResponse validates .well-known response structure
func ValidateWellKnownResponse(response *WellKnownResponse) bool {
	return response != nil &&
		response.SchemaVersion != "" &&
		response.PublicKeyPEM != ""
}

// FetchWellKnown fetches and validates .well-known/schemapin.json from domain
func (p *PublicKeyDiscovery) FetchWellKnown(ctx context.Context, domainName string) (*WellKnownResponse, error) {
	wellKnownURL, err := p.ConstructWellKnownURL(domainName)
	if err != nil {
		return nil, err
	}

	var wellKnown WellKnownResponse
	if err := transport.FetchJSON(ctx, p.client, wellKnownURL, &wellKnown); err != nil {
		return nil, fmt.Errorf("failed to fetch .well-known file: %w", err)
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
		// A key that cannot be fingerprinted cannot be trusted either.
		return true
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

// ValidateKeyNotRevoked validates that a public key is not revoked (fail-closed).
//
// Consults both the inline revoked_keys list and, when the discovery document
// declares one, the standalone revocation_endpoint. If either cannot be fetched
// the key is treated as not validated: (false, err) is returned. Callers that
// want to proceed anyway must do so explicitly.
func (p *PublicKeyDiscovery) ValidateKeyNotRevoked(ctx context.Context, publicKeyPEM, domainName string) (bool, error) {
	wellKnown, err := p.FetchWellKnown(ctx, domainName)
	if err != nil {
		return false, fmt.Errorf("revocation status unavailable (fail-closed): %w", err)
	}
	if CheckKeyRevocation(publicKeyPEM, wellKnown.RevokedKeys) {
		return false, nil
	}
	if wellKnown.RevocationEndpoint != "" {
		doc, err := revocation.FetchRevocationDocumentWithClient(ctx, p.client, wellKnown.RevocationEndpoint)
		if err != nil {
			return false, fmt.Errorf("revocation status unavailable (fail-closed): %w", err)
		}
		fingerprint, err := p.keyManager.CalculateKeyFingerprintFromPEM(publicKeyPEM)
		if err != nil {
			return false, err
		}
		if err := revocation.CheckRevocation(doc, fingerprint); err != nil {
			return false, nil
		}
	}
	return true, nil
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
