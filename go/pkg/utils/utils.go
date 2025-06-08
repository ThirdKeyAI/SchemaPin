// Package utils provides high-level workflows for SchemaPin operations.
package utils

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"strings"
	"time"

	"github.com/ThirdKeyAi/schemapin/go/pkg/core"
	"github.com/ThirdKeyAi/schemapin/go/pkg/crypto"
	"github.com/ThirdKeyAi/schemapin/go/pkg/discovery"
	"github.com/ThirdKeyAi/schemapin/go/pkg/pinning"
)

// SchemaSigningWorkflow provides high-level signing operations
type SchemaSigningWorkflow struct {
	privateKey       *ecdsa.PrivateKey
	keyManager       *crypto.KeyManager
	signatureManager *crypto.SignatureManager
	core             *core.SchemaPinCore
}

// NewSchemaSigningWorkflow creates a new signing workflow
func NewSchemaSigningWorkflow(privateKeyPEM string) (*SchemaSigningWorkflow, error) {
	if privateKeyPEM == "" {
		return nil, fmt.Errorf("private key PEM cannot be empty")
	}

	keyManager := crypto.NewKeyManager()
	privateKey, err := keyManager.LoadPrivateKeyPEM(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	return &SchemaSigningWorkflow{
		privateKey:       privateKey,
		keyManager:       keyManager,
		signatureManager: crypto.NewSignatureManager(),
		core:             core.NewSchemaPinCore(),
	}, nil
}

// SignSchema signs a schema and returns the base64-encoded signature
func (s *SchemaSigningWorkflow) SignSchema(schema map[string]interface{}) (string, error) {
	if err := s.core.ValidateSchema(schema); err != nil {
		return "", fmt.Errorf("schema validation failed: %w", err)
	}

	schemaHash, err := s.core.CanonicalizeAndHash(schema)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize and hash schema: %w", err)
	}

	signature, err := s.signatureManager.SignSchemaHash(schemaHash, s.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign schema hash: %w", err)
	}

	return signature, nil
}

// GetPublicKeyPEM returns the PEM-encoded public key for this signing workflow
func (s *SchemaSigningWorkflow) GetPublicKeyPEM() (string, error) {
	return s.keyManager.ExportPublicKeyPEM(&s.privateKey.PublicKey)
}

// SchemaVerificationWorkflow provides high-level verification operations
type SchemaVerificationWorkflow struct {
	pinning          *pinning.KeyPinning
	discovery        *discovery.PublicKeyDiscovery
	keyManager       *crypto.KeyManager
	signatureManager *crypto.SignatureManager
	core             *core.SchemaPinCore
}

// VerificationResult contains the result of schema verification
type VerificationResult struct {
	Valid         bool                   `json:"valid"`
	Pinned        bool                   `json:"pinned"`
	FirstUse      bool                   `json:"first_use"`
	Error         string                 `json:"error,omitempty"`
	DeveloperInfo map[string]string      `json:"developer_info,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// NewSchemaVerificationWorkflow creates a new verification workflow
func NewSchemaVerificationWorkflow(pinningDBPath string) (*SchemaVerificationWorkflow, error) {
	keyPinning, err := pinning.NewKeyPinning(pinningDBPath, pinning.PinningModeInteractive, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize key pinning: %w", err)
	}

	return &SchemaVerificationWorkflow{
		pinning:          keyPinning,
		discovery:        discovery.NewPublicKeyDiscovery(),
		keyManager:       crypto.NewKeyManager(),
		signatureManager: crypto.NewSignatureManager(),
		core:             core.NewSchemaPinCore(),
	}, nil
}

// NewSchemaVerificationWorkflowWithPinning creates a new verification workflow with existing pinning
func NewSchemaVerificationWorkflowWithPinning(keyPinning *pinning.KeyPinning) *SchemaVerificationWorkflow {
	return &SchemaVerificationWorkflow{
		pinning:          keyPinning,
		discovery:        discovery.NewPublicKeyDiscovery(),
		keyManager:       crypto.NewKeyManager(),
		signatureManager: crypto.NewSignatureManager(),
		core:             core.NewSchemaPinCore(),
	}
}

// Close closes the verification workflow and releases resources
func (s *SchemaVerificationWorkflow) Close() error {
	if s.pinning != nil {
		return s.pinning.Close()
	}
	return nil
}

// VerifySchema verifies a signed schema with optional auto-pinning
func (s *SchemaVerificationWorkflow) VerifySchema(ctx context.Context, schema map[string]interface{}, signatureB64, toolID, domain string, autoPin bool) (*VerificationResult, error) {
	result := &VerificationResult{
		Valid:    false,
		Pinned:   false,
		FirstUse: false,
		Metadata: make(map[string]interface{}),
	}

	// Validate schema first
	if err := s.core.ValidateSchema(schema); err != nil {
		result.Error = fmt.Sprintf("schema validation failed: %v", err)
		return result, nil
	}

	// Canonicalize and hash schema
	schemaHash, err := s.core.CanonicalizeAndHash(schema)
	if err != nil {
		result.Error = fmt.Sprintf("failed to canonicalize schema: %v", err)
		return result, nil
	}

	// Check for pinned key
	pinnedKeyPEM, err := s.pinning.GetPinnedKey(toolID)
	if err != nil {
		result.Error = fmt.Sprintf("failed to check pinned key: %v", err)
		return result, nil
	}

	var publicKeyPEM string
	var publicKey *ecdsa.PublicKey

	if pinnedKeyPEM != "" {
		// Use pinned key, but check if it's been revoked
		isNotRevoked, err := s.discovery.ValidateKeyNotRevoked(ctx, pinnedKeyPEM, domain)
		if err != nil {
			// If we can't check revocation, proceed with caution
			isNotRevoked = true
		}

		if !isNotRevoked {
			result.Error = "pinned public key has been revoked"
			return result, nil
		}

		publicKey, err = s.keyManager.LoadPublicKeyPEM(pinnedKeyPEM)
		if err != nil {
			result.Error = fmt.Sprintf("failed to load pinned public key: %v", err)
			return result, nil
		}

		publicKeyPEM = pinnedKeyPEM
		result.Pinned = true
	} else {
		// First use - discover key
		discoveredKeyPEM, err := s.discovery.GetPublicKeyPEM(ctx, domain)
		if err != nil {
			result.Error = fmt.Sprintf("could not discover public key: %v", err)
			return result, nil
		}

		// Check if key is revoked
		isNotRevoked, err := s.discovery.ValidateKeyNotRevoked(ctx, discoveredKeyPEM, domain)
		if err != nil {
			// If we can't check revocation, proceed with caution
			isNotRevoked = true
		}

		if !isNotRevoked {
			result.Error = "public key has been revoked"
			return result, nil
		}

		publicKey, err = s.keyManager.LoadPublicKeyPEM(discoveredKeyPEM)
		if err != nil {
			result.Error = fmt.Sprintf("failed to load discovered public key: %v", err)
			return result, nil
		}

		publicKeyPEM = discoveredKeyPEM
		result.FirstUse = true

		// Get developer info
		developerInfo, err := s.discovery.GetDeveloperInfo(ctx, domain)
		if err == nil {
			result.DeveloperInfo = developerInfo
		}

		// Auto-pin if requested
		if autoPin {
			developerName := ""
			if result.DeveloperInfo != nil {
				if name, ok := result.DeveloperInfo["developer_name"]; ok {
					developerName = name
				}
			}

			if err := s.pinning.PinKey(toolID, publicKeyPEM, domain, developerName); err == nil {
				result.Pinned = true
			}
		}
	}

	// Verify signature
	result.Valid = s.signatureManager.VerifySchemaSignature(schemaHash, signatureB64, publicKey)

	// Update verification timestamp if valid and pinned
	if result.Valid && result.Pinned {
		s.pinning.UpdateLastVerified(toolID)
	}

	// Add metadata
	if fingerprint, err := s.keyManager.CalculateKeyFingerprintFromPEM(publicKeyPEM); err == nil {
		result.Metadata["key_fingerprint"] = fingerprint
	}
	result.Metadata["domain"] = domain
	result.Metadata["tool_id"] = toolID

	return result, nil
}

// PinKeyForTool manually pins a key for a specific tool
func (s *SchemaVerificationWorkflow) PinKeyForTool(ctx context.Context, toolID, domain, developerName string) error {
	publicKeyPEM, err := s.discovery.GetPublicKeyPEM(ctx, domain)
	if err != nil {
		return fmt.Errorf("failed to discover public key: %w", err)
	}

	// Check if key is revoked
	isNotRevoked, err := s.discovery.ValidateKeyNotRevoked(ctx, publicKeyPEM, domain)
	if err != nil {
		return fmt.Errorf("failed to check key revocation: %w", err)
	}

	if !isNotRevoked {
		return fmt.Errorf("public key has been revoked")
	}

	// Pin the key
	if err := s.pinning.PinKey(toolID, publicKeyPEM, domain, developerName); err != nil {
		return fmt.Errorf("failed to pin key: %w", err)
	}

	return nil
}

// GetPinnedKeyInfo retrieves information about a pinned key
func (s *SchemaVerificationWorkflow) GetPinnedKeyInfo(toolID string) (*pinning.PinnedKeyInfo, error) {
	return s.pinning.GetKeyInfo(toolID)
}

// ListPinnedKeys lists all pinned keys
func (s *SchemaVerificationWorkflow) ListPinnedKeys() ([]map[string]interface{}, error) {
	return s.pinning.ListPinnedKeys()
}

// RemovePinnedKey removes a pinned key
func (s *SchemaVerificationWorkflow) RemovePinnedKey(toolID string) error {
	return s.pinning.RemovePinnedKey(toolID)
}

// CreateWellKnownResponse creates a .well-known response structure
func CreateWellKnownResponse(publicKeyPEM, developerName, contact string, revokedKeys []string, schemaVersion string) map[string]interface{} {
	if schemaVersion == "" {
		schemaVersion = "1.1"
	}

	response := map[string]interface{}{
		"schema_version": schemaVersion,
		"developer_name": developerName,
		"public_key_pem": publicKeyPEM,
	}

	if contact != "" {
		response["contact"] = contact
	}

	if len(revokedKeys) > 0 {
		response["revoked_keys"] = revokedKeys
	}

	return response
}

// ValidateSchema performs basic schema validation
func ValidateSchema(schema map[string]interface{}) error {
	if schema == nil {
		return fmt.Errorf("schema cannot be nil")
	}

	if len(schema) == 0 {
		return fmt.Errorf("schema cannot be empty")
	}

	// Use core validation
	core := core.NewSchemaPinCore()
	return core.ValidateSchema(schema)
}

// FormatKeyFingerprint formats a key fingerprint for display
func FormatKeyFingerprint(fingerprint string) string {
	if len(fingerprint) < 16 {
		return fingerprint
	}

	// Remove "sha256:" prefix if present
	if strings.HasPrefix(fingerprint, "sha256:") {
		fingerprint = fingerprint[7:]
	}

	// Format as groups of 4 characters separated by colons
	var formatted strings.Builder
	for i, char := range fingerprint {
		if i > 0 && i%4 == 0 {
			formatted.WriteString(":")
		}
		formatted.WriteRune(char)
	}

	result := formatted.String()
	if len(result) > 23 { // Show first 8 and last 8 characters with ellipsis
		return result[:11] + "..." + result[len(result)-11:]
	}

	return result
}

// CalculateSchemaHash calculates the hash of a schema for verification
func CalculateSchemaHash(schema map[string]interface{}) ([]byte, error) {
	core := core.NewSchemaPinCore()
	return core.CanonicalizeAndHash(schema)
}

// VerifySignatureOnly verifies a signature against a schema hash and public key
func VerifySignatureOnly(schemaHash []byte, signatureB64, publicKeyPEM string) (bool, error) {
	keyManager := crypto.NewKeyManager()
	publicKey, err := keyManager.LoadPublicKeyPEM(publicKeyPEM)
	if err != nil {
		return false, fmt.Errorf("failed to load public key: %w", err)
	}

	signatureManager := crypto.NewSignatureManager()
	return signatureManager.VerifySchemaSignature(schemaHash, signatureB64, publicKey), nil
}

// GenerateKeyPair generates a new ECDSA key pair and returns PEM-encoded strings
func GenerateKeyPair() (privateKeyPEM, publicKeyPEM string, err error) {
	keyManager := crypto.NewKeyManager()

	privateKey, err := keyManager.GenerateKeypair()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate key pair: %w", err)
	}

	privateKeyPEM, err = keyManager.ExportPrivateKeyPEM(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to export private key: %w", err)
	}

	publicKeyPEM, err = keyManager.ExportPublicKeyPEM(&privateKey.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to export public key: %w", err)
	}

	return privateKeyPEM, publicKeyPEM, nil
}

// SchemaVerificationError represents errors that occur during schema verification
type SchemaVerificationError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

func (e *SchemaVerificationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

// NewSchemaVerificationError creates a new schema verification error
func NewSchemaVerificationError(errorType, message, code string) *SchemaVerificationError {
	return &SchemaVerificationError{
		Type:    errorType,
		Message: message,
		Code:    code,
	}
}

// Common error types
var (
	ErrSchemaInvalid      = "SCHEMA_INVALID"
	ErrSignatureInvalid   = "SIGNATURE_INVALID"
	ErrKeyNotFound        = "KEY_NOT_FOUND"
	ErrKeyRevoked         = "KEY_REVOKED"
	ErrKeyExpired         = "KEY_EXPIRED"
	ErrDiscoveryFailed    = "DISCOVERY_FAILED"
	ErrPinningFailed      = "PINNING_FAILED"
	ErrVerificationFailed = "VERIFICATION_FAILED"
)

// IsTemporaryError checks if an error is temporary and verification should be retried
func IsTemporaryError(err error) bool {
	if err == nil {
		return false
	}

	errorStr := err.Error()
	temporaryIndicators := []string{
		"timeout",
		"connection refused",
		"network",
		"temporary",
		"unavailable",
	}

	for _, indicator := range temporaryIndicators {
		if strings.Contains(strings.ToLower(errorStr), indicator) {
			return true
		}
	}

	return false
}

// RetryVerification retries schema verification with exponential backoff
func RetryVerification(ctx context.Context, workflow *SchemaVerificationWorkflow, schema map[string]interface{}, signatureB64, toolID, domain string, autoPin bool, maxRetries int) (*VerificationResult, error) {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		result, err := workflow.VerifySchema(ctx, schema, signatureB64, toolID, domain, autoPin)
		if err == nil && (result.Valid || !IsTemporaryError(fmt.Errorf(result.Error))) {
			return result, nil
		}

		if err != nil {
			lastErr = err
			if !IsTemporaryError(err) {
				return nil, err
			}
		} else {
			lastErr = fmt.Errorf(result.Error)
			if !IsTemporaryError(lastErr) {
				return result, nil
			}
		}

		if attempt < maxRetries {
			// Exponential backoff: 1s, 2s, 4s, 8s, etc.
			backoff := time.Duration(1<<uint(attempt)) * time.Second
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
				continue
			}
		}
	}

	return nil, fmt.Errorf("verification failed after %d retries: %w", maxRetries, lastErr)
}
