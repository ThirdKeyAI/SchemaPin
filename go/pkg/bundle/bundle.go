// Package bundle provides trust bundles for offline/air-gapped SchemaPin verification.
package bundle

import (
	"encoding/json"
	"fmt"

	"github.com/ThirdKeyAi/schemapin/go/pkg/discovery"
	"github.com/ThirdKeyAi/schemapin/go/pkg/revocation"
)

// BundledDiscovery combines a domain with its well-known response.
// Uses custom JSON marshaling for flattened format.
type BundledDiscovery struct {
	Domain   string
	WellKnown discovery.WellKnownResponse
}

// MarshalJSON implements custom JSON marshaling with flattened format.
func (b BundledDiscovery) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{
		"domain":         b.Domain,
		"schema_version": b.WellKnown.SchemaVersion,
		"developer_name": b.WellKnown.DeveloperName,
		"public_key_pem": b.WellKnown.PublicKeyPEM,
	}
	if b.WellKnown.Contact != "" {
		m["contact"] = b.WellKnown.Contact
	}
	if len(b.WellKnown.RevokedKeys) > 0 {
		m["revoked_keys"] = b.WellKnown.RevokedKeys
	}
	if b.WellKnown.RevocationEndpoint != "" {
		m["revocation_endpoint"] = b.WellKnown.RevocationEndpoint
	}
	return json.Marshal(m)
}

// UnmarshalJSON implements custom JSON unmarshaling from flattened format.
func (b *BundledDiscovery) UnmarshalJSON(data []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}

	if v, ok := m["domain"]; ok {
		if err := json.Unmarshal(v, &b.Domain); err != nil {
			return fmt.Errorf("failed to unmarshal domain: %w", err)
		}
	}

	// Unmarshal the well-known fields directly from the flat map
	wellKnownData, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return json.Unmarshal(wellKnownData, &b.WellKnown)
}

// SchemaPinTrustBundle holds discovery documents and revocations for offline use.
type SchemaPinTrustBundle struct {
	SchemapinBundleVersion string                       `json:"schemapin_bundle_version"`
	CreatedAt              string                       `json:"created_at"`
	Documents              []BundledDiscovery           `json:"documents"`
	Revocations            []revocation.RevocationDocument `json:"revocations"`
}

// NewTrustBundle creates a new empty trust bundle.
func NewTrustBundle(createdAt string) *SchemaPinTrustBundle {
	return &SchemaPinTrustBundle{
		SchemapinBundleVersion: "1.2",
		CreatedAt:              createdAt,
		Documents:              []BundledDiscovery{},
		Revocations:            []revocation.RevocationDocument{},
	}
}

// FindDiscovery finds a discovery document for a domain.
func (b *SchemaPinTrustBundle) FindDiscovery(domain string) *discovery.WellKnownResponse {
	for i := range b.Documents {
		if b.Documents[i].Domain == domain {
			return &b.Documents[i].WellKnown
		}
	}
	return nil
}

// FindRevocation finds a revocation document for a domain.
func (b *SchemaPinTrustBundle) FindRevocation(domain string) *revocation.RevocationDocument {
	for i := range b.Revocations {
		if b.Revocations[i].Domain == domain {
			return &b.Revocations[i]
		}
	}
	return nil
}

// ParseTrustBundle parses a trust bundle from a JSON string.
func ParseTrustBundle(jsonStr string) (*SchemaPinTrustBundle, error) {
	var bundle SchemaPinTrustBundle
	if err := json.Unmarshal([]byte(jsonStr), &bundle); err != nil {
		return nil, fmt.Errorf("failed to parse trust bundle: %w", err)
	}
	return &bundle, nil
}
