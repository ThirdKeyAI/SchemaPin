// Package verification provides offline and resolver-based schema verification for SchemaPin v1.2.
package verification

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ThirdKeyAi/schemapin/go/pkg/core"
	"github.com/ThirdKeyAi/schemapin/go/pkg/crypto"
	"github.com/ThirdKeyAi/schemapin/go/pkg/discovery"
	"github.com/ThirdKeyAi/schemapin/go/pkg/resolver"
	"github.com/ThirdKeyAi/schemapin/go/pkg/revocation"
)

// ErrorCode represents structured error codes for verification results.
type ErrorCode string

const (
	ErrSignatureInvalid             ErrorCode = "signature_invalid"
	ErrKeyNotFound                  ErrorCode = "key_not_found"
	ErrKeyRevoked                   ErrorCode = "key_revoked"
	ErrKeyPinMismatch               ErrorCode = "key_pin_mismatch"
	ErrDiscoveryFetchFailed         ErrorCode = "discovery_fetch_failed"
	ErrDiscoveryInvalid             ErrorCode = "discovery_invalid"
	ErrDomainMismatch               ErrorCode = "domain_mismatch"
	ErrSchemaCanonicalizationFailed ErrorCode = "schema_canonicalization_failed"
)

// KeyPinningStatus represents the pinning status in a verification result.
type KeyPinningStatus struct {
	Status    string `json:"status"`
	FirstSeen string `json:"first_seen,omitempty"`
}

// VerificationResult is the structured result from schema verification.
type VerificationResult struct {
	Valid         bool              `json:"valid"`
	Domain        string            `json:"domain,omitempty"`
	DeveloperName string            `json:"developer_name,omitempty"`
	KeyPinning    *KeyPinningStatus `json:"key_pinning,omitempty"`
	ErrorCode     ErrorCode         `json:"error_code,omitempty"`
	ErrorMessage  string            `json:"error_message,omitempty"`
	Warnings      []string          `json:"warnings,omitempty"`
}

// PinResult represents the result of a pin check.
type PinResult string

const (
	PinFirstUse PinResult = "first_use"
	PinPinned   PinResult = "pinned"
	PinChanged  PinResult = "changed"
)

// KeyPinStore is a lightweight in-memory fingerprint-based pin store.
// Keys are stored by tool_id@domain.
type KeyPinStore struct {
	pins map[string]string
}

// NewKeyPinStore creates a new empty KeyPinStore.
func NewKeyPinStore() *KeyPinStore {
	return &KeyPinStore{pins: make(map[string]string)}
}

func pinKey(toolID, domain string) string {
	return toolID + "@" + domain
}

// CheckAndPin checks and optionally pins a key fingerprint.
func (s *KeyPinStore) CheckAndPin(toolID, domain, fingerprint string) PinResult {
	k := pinKey(toolID, domain)
	existing, ok := s.pins[k]
	if !ok {
		s.pins[k] = fingerprint
		return PinFirstUse
	}
	if existing == fingerprint {
		return PinPinned
	}
	return PinChanged
}

// GetPinned returns the pinned fingerprint for a tool@domain, or empty string.
func (s *KeyPinStore) GetPinned(toolID, domain string) string {
	return s.pins[pinKey(toolID, domain)]
}

// ToJSON serializes the pin store to JSON.
func (s *KeyPinStore) ToJSON() (string, error) {
	data, err := json.Marshal(s.pins)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// FromJSON deserializes a pin store from JSON.
func FromJSON(jsonStr string) (*KeyPinStore, error) {
	store := NewKeyPinStore()
	if err := json.Unmarshal([]byte(jsonStr), &store.pins); err != nil {
		return nil, err
	}
	return store, nil
}

// VerifySchemaOffline verifies a schema offline using pre-fetched discovery and revocation data.
//
// 7-step verification flow:
// 1. Validate discovery document
// 2. Extract public key and compute fingerprint
// 3. Check revocation (both simple list + standalone doc)
// 4. TOFU key pinning check
// 5. Canonicalize schema and compute hash
// 6. Verify ECDSA signature against hash
// 7. Return structured result
func VerifySchemaOffline(
	schema map[string]interface{},
	signatureB64 string,
	domain string,
	toolID string,
	disc *discovery.WellKnownResponse,
	rev *revocation.RevocationDocument,
	pinStore *KeyPinStore,
) *VerificationResult {
	// Step 1: Validate discovery document
	if disc == nil || disc.PublicKeyPEM == "" || !strings.Contains(disc.PublicKeyPEM, "-----BEGIN PUBLIC KEY-----") {
		return &VerificationResult{
			Valid:        false,
			Domain:       domain,
			ErrorCode:    ErrDiscoveryInvalid,
			ErrorMessage: "Discovery document missing or invalid public_key_pem",
		}
	}

	// Step 2: Extract public key and compute fingerprint
	keyManager := crypto.NewKeyManager()
	publicKey, err := keyManager.LoadPublicKeyPEM(disc.PublicKeyPEM)
	if err != nil {
		return &VerificationResult{
			Valid:        false,
			Domain:       domain,
			ErrorCode:    ErrKeyNotFound,
			ErrorMessage: fmt.Sprintf("Failed to load public key: %v", err),
		}
	}

	fingerprint, err := keyManager.CalculateKeyFingerprintFromPEM(disc.PublicKeyPEM)
	if err != nil {
		return &VerificationResult{
			Valid:        false,
			Domain:       domain,
			ErrorCode:    ErrKeyNotFound,
			ErrorMessage: fmt.Sprintf("Failed to calculate fingerprint: %v", err),
		}
	}

	// Step 3: Check revocation
	if err := revocation.CheckRevocationCombined(disc.RevokedKeys, rev, fingerprint); err != nil {
		return &VerificationResult{
			Valid:        false,
			Domain:       domain,
			ErrorCode:    ErrKeyRevoked,
			ErrorMessage: err.Error(),
		}
	}

	// Step 4: TOFU key pinning
	pinResult := pinStore.CheckAndPin(toolID, domain, fingerprint)
	if pinResult == PinChanged {
		return &VerificationResult{
			Valid:        false,
			Domain:       domain,
			ErrorCode:    ErrKeyPinMismatch,
			ErrorMessage: "Key fingerprint changed since last use",
		}
	}

	// Step 5: Canonicalize and hash
	c := core.NewSchemaPinCore()
	schemaHash, err := c.CanonicalizeAndHash(schema)
	if err != nil {
		return &VerificationResult{
			Valid:        false,
			Domain:       domain,
			ErrorCode:    ErrSchemaCanonicalizationFailed,
			ErrorMessage: fmt.Sprintf("Failed to canonicalize schema: %v", err),
		}
	}

	// Step 6: Verify signature
	sigManager := crypto.NewSignatureManager()
	valid := sigManager.VerifySchemaSignature(schemaHash, signatureB64, publicKey)

	if !valid {
		return &VerificationResult{
			Valid:        false,
			Domain:       domain,
			ErrorCode:    ErrSignatureInvalid,
			ErrorMessage: "Signature verification failed",
		}
	}

	// Step 7: Return success
	result := &VerificationResult{
		Valid:         true,
		Domain:        domain,
		DeveloperName: disc.DeveloperName,
		KeyPinning: &KeyPinningStatus{
			Status: string(pinResult),
		},
		Warnings: []string{},
	}

	if disc.SchemaVersion != "" && disc.SchemaVersion < "1.2" {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Discovery uses schema version %s, consider upgrading to 1.2", disc.SchemaVersion))
	}

	return result
}

// VerifySchemaWithResolver verifies a schema using a resolver for discovery and revocation.
func VerifySchemaWithResolver(
	schema map[string]interface{},
	signatureB64 string,
	domain string,
	toolID string,
	r resolver.SchemaResolver,
	pinStore *KeyPinStore,
) *VerificationResult {
	disc, err := r.ResolveDiscovery(domain)
	if err != nil {
		return &VerificationResult{
			Valid:        false,
			Domain:       domain,
			ErrorCode:    ErrDiscoveryFetchFailed,
			ErrorMessage: fmt.Sprintf("Could not resolve discovery for domain: %s", domain),
		}
	}

	rev, _ := r.ResolveRevocation(domain, disc)

	return VerifySchemaOffline(schema, signatureB64, domain, toolID, disc, rev, pinStore)
}
