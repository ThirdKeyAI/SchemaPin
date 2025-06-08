// Package utils provides high-level workflows for SchemaPin operations.
package utils

import (
	"context"
	"fmt"
)

// SchemaSigningWorkflow provides high-level signing operations
type SchemaSigningWorkflow struct {
	privateKeyPEM string
	// TODO: Add crypto and core components
}

// NewSchemaSigningWorkflow creates a new signing workflow
func NewSchemaSigningWorkflow(privateKeyPEM string) (*SchemaSigningWorkflow, error) {
	if privateKeyPEM == "" {
		return nil, fmt.Errorf("private key PEM cannot be empty")
	}

	return &SchemaSigningWorkflow{
		privateKeyPEM: privateKeyPEM,
	}, nil
}

// SignSchema signs a schema and returns the signature
func (s *SchemaSigningWorkflow) SignSchema(schema map[string]interface{}) (string, error) {
	// TODO: Implement schema signing workflow:
	// 1. Canonicalize schema using core package
	// 2. Hash canonical representation
	// 3. Sign hash using crypto package
	// 4. Return base64-encoded signature
	return "", fmt.Errorf("not implemented")
}

// SchemaVerificationWorkflow provides high-level verification operations
type SchemaVerificationWorkflow struct {
	pinningDBPath string
	// TODO: Add pinning, discovery, and crypto components
}

// NewSchemaVerificationWorkflow creates a new verification workflow
func NewSchemaVerificationWorkflow(pinningDBPath string) (*SchemaVerificationWorkflow, error) {
	if pinningDBPath == "" {
		return nil, fmt.Errorf("pinning database path cannot be empty")
	}

	return &SchemaVerificationWorkflow{
		pinningDBPath: pinningDBPath,
	}, nil
}

// VerifySchema verifies a signed schema with optional auto-pinning
func (s *SchemaVerificationWorkflow) VerifySchema(ctx context.Context, schema map[string]interface{}, signatureB64, toolID, domain string, autoPin bool) (map[string]interface{}, error) {
	// TODO: Implement schema verification workflow:
	// 1. Canonicalize and hash schema
	// 2. Check for pinned key or discover via .well-known
	// 3. Verify signature against public key
	// 4. Handle key pinning if needed
	// 5. Return verification result
	return nil, fmt.Errorf("not implemented")
}

// PinKeyForTool manually pins a key for a specific tool
func (s *SchemaVerificationWorkflow) PinKeyForTool(ctx context.Context, toolID, domain, developerName string) error {
	// TODO: Implement manual key pinning:
	// 1. Discover public key via .well-known endpoint
	// 2. Validate key is not revoked
	// 3. Store in pinning database
	return fmt.Errorf("not implemented")
}

// CreateWellKnownResponse creates a .well-known response structure
func CreateWellKnownResponse(publicKeyPEM, developerName, contact string, revokedKeys []string, schemaVersion string) map[string]interface{} {
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
	// TODO: Implement schema validation logic
	if schema == nil {
		return fmt.Errorf("schema cannot be nil")
	}

	if len(schema) == 0 {
		return fmt.Errorf("schema cannot be empty")
	}

	return nil
}

// FormatKeyFingerprint formats a key fingerprint for display
func FormatKeyFingerprint(fingerprint string) string {
	// TODO: Implement fingerprint formatting (e.g., with colons every 2 chars)
	if len(fingerprint) < 8 {
		return fingerprint
	}
	return fingerprint[:8] + "..." + fingerprint[len(fingerprint)-8:]
}
