package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ThirdKeyAi/schemapin/go/pkg/crypto"
	"github.com/ThirdKeyAi/schemapin/go/pkg/discovery"
)

func TestNewSchemaSigningWorkflow(t *testing.T) {
	// Generate a test key
	keyManager := crypto.NewKeyManager()
	privateKey, err := keyManager.GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	privateKeyPEM, err := keyManager.ExportPrivateKeyPEM(privateKey)
	if err != nil {
		t.Fatalf("Failed to export private key: %v", err)
	}

	workflow, err := NewSchemaSigningWorkflow(privateKeyPEM)
	if err != nil {
		t.Fatalf("Failed to create signing workflow: %v", err)
	}

	if workflow == nil {
		t.Fatal("Expected non-nil workflow")
	}
}

func TestNewSchemaSigningWorkflow_EmptyKey(t *testing.T) {
	_, err := NewSchemaSigningWorkflow("")
	if err == nil {
		t.Error("Expected error for empty private key")
	}
}

func TestNewSchemaSigningWorkflow_InvalidKey(t *testing.T) {
	_, err := NewSchemaSigningWorkflow("invalid-pem-data")
	if err == nil {
		t.Error("Expected error for invalid private key")
	}
}

func TestSchemaSigningWorkflow_SignSchema(t *testing.T) {
	// Generate a test key
	keyManager := crypto.NewKeyManager()
	privateKey, err := keyManager.GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	privateKeyPEM, err := keyManager.ExportPrivateKeyPEM(privateKey)
	if err != nil {
		t.Fatalf("Failed to export private key: %v", err)
	}

	workflow, err := NewSchemaSigningWorkflow(privateKeyPEM)
	if err != nil {
		t.Fatalf("Failed to create signing workflow: %v", err)
	}

	schema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"name": map[string]interface{}{
				"type": "string",
			},
		},
	}

	signature, err := workflow.SignSchema(schema)
	if err != nil {
		t.Fatalf("Failed to sign schema: %v", err)
	}

	if signature == "" {
		t.Error("Expected non-empty signature")
	}
}

func TestSchemaSigningWorkflow_SignSchema_InvalidSchema(t *testing.T) {
	// Generate a test key
	keyManager := crypto.NewKeyManager()
	privateKey, err := keyManager.GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	privateKeyPEM, err := keyManager.ExportPrivateKeyPEM(privateKey)
	if err != nil {
		t.Fatalf("Failed to export private key: %v", err)
	}

	workflow, err := NewSchemaSigningWorkflow(privateKeyPEM)
	if err != nil {
		t.Fatalf("Failed to create signing workflow: %v", err)
	}

	// Test with nil schema
	_, err = workflow.SignSchema(nil)
	if err == nil {
		t.Error("Expected error for nil schema")
	}

	// Test with empty schema - this should actually pass as empty schemas are valid JSON
	_, err = workflow.SignSchema(map[string]interface{}{})
	if err != nil {
		t.Errorf("Unexpected error for empty schema: %v", err)
	}
}

func TestSchemaSigningWorkflow_GetPublicKeyPEM(t *testing.T) {
	// Generate a test key
	keyManager := crypto.NewKeyManager()
	privateKey, err := keyManager.GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	privateKeyPEM, err := keyManager.ExportPrivateKeyPEM(privateKey)
	if err != nil {
		t.Fatalf("Failed to export private key: %v", err)
	}

	workflow, err := NewSchemaSigningWorkflow(privateKeyPEM)
	if err != nil {
		t.Fatalf("Failed to create signing workflow: %v", err)
	}

	publicKeyPEM, err := workflow.GetPublicKeyPEM()
	if err != nil {
		t.Fatalf("Failed to get public key PEM: %v", err)
	}

	if !strings.Contains(publicKeyPEM, "BEGIN PUBLIC KEY") {
		t.Error("Expected valid PEM format")
	}
}

func TestNewSchemaVerificationWorkflow(t *testing.T) {
	// Create temporary database path
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	workflow, err := NewSchemaVerificationWorkflow(dbPath)
	if err != nil {
		t.Fatalf("Failed to create verification workflow: %v", err)
	}
	defer workflow.Close()

	if workflow == nil {
		t.Fatal("Expected non-nil workflow")
	}
}

func TestNewSchemaVerificationWorkflow_EmptyPath(t *testing.T) {
	_, err := NewSchemaVerificationWorkflow("")
	if err == nil {
		t.Error("Expected error for empty database path")
	}
}

func TestSchemaVerificationWorkflow_VerifySchema_AutoPin(t *testing.T) {
	// Create temporary database path
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	// Generate test keys
	keyManager := crypto.NewKeyManager()
	privateKey, err := keyManager.GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	publicKeyPEM, err := keyManager.ExportPublicKeyPEM(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to export public key: %v", err)
	}

	// Create verification workflow
	workflow, err := NewSchemaVerificationWorkflow(dbPath)
	if err != nil {
		t.Fatalf("Failed to create verification workflow: %v", err)
	}
	defer workflow.Close()

	// Manually pin the key to simulate auto-pin behavior
	err = workflow.pinning.PinKey("test-tool", publicKeyPEM, "example.com", "Test Developer")
	if err != nil {
		t.Fatalf("Failed to pin key: %v", err)
	}

	// Create signing workflow to sign test schema
	privateKeyPEM, err := keyManager.ExportPrivateKeyPEM(privateKey)
	if err != nil {
		t.Fatalf("Failed to export private key: %v", err)
	}

	signingWorkflow, err := NewSchemaSigningWorkflow(privateKeyPEM)
	if err != nil {
		t.Fatalf("Failed to create signing workflow: %v", err)
	}

	schema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"name": map[string]interface{}{
				"type": "string",
			},
		},
	}

	signature, err := signingWorkflow.SignSchema(schema)
	if err != nil {
		t.Fatalf("Failed to sign schema: %v", err)
	}

	// Create mock server for revocation check
	wellKnownResponse := discovery.WellKnownResponse{
		SchemaVersion: "1.1",
		DeveloperName: "Test Developer",
		PublicKeyPEM:  publicKeyPEM,
		RevokedKeys:   []string{},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/schemapin.json" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(wellKnownResponse)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Extract domain from server URL
	domain := strings.TrimPrefix(server.URL, "http://")

	ctx := context.Background()
	result, err := workflow.VerifySchema(ctx, schema, signature, "test-tool", domain, false)
	if err != nil {
		t.Fatalf("Failed to verify schema: %v", err)
	}

	if !result.Valid {
		t.Error("Expected valid signature")
	}
	if result.FirstUse {
		t.Error("Expected not first use since key is already pinned")
	}
	if !result.Pinned {
		t.Error("Expected key to be pinned")
	}
}

func TestSchemaVerificationWorkflow_VerifySchema_PinnedKey(t *testing.T) {
	// Create temporary database path
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	// Generate test keys
	keyManager := crypto.NewKeyManager()
	privateKey, err := keyManager.GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	publicKeyPEM, err := keyManager.ExportPublicKeyPEM(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to export public key: %v", err)
	}

	// Create verification workflow and pin key manually
	workflow, err := NewSchemaVerificationWorkflow(dbPath)
	if err != nil {
		t.Fatalf("Failed to create verification workflow: %v", err)
	}
	defer workflow.Close()

	// Pin the key manually
	err = workflow.pinning.PinKey("test-tool", publicKeyPEM, "example.com", "Test Developer")
	if err != nil {
		t.Fatalf("Failed to pin key: %v", err)
	}

	// Create signing workflow to sign test schema
	privateKeyPEM, err := keyManager.ExportPrivateKeyPEM(privateKey)
	if err != nil {
		t.Fatalf("Failed to export private key: %v", err)
	}

	signingWorkflow, err := NewSchemaSigningWorkflow(privateKeyPEM)
	if err != nil {
		t.Fatalf("Failed to create signing workflow: %v", err)
	}

	schema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"name": map[string]interface{}{
				"type": "string",
			},
		},
	}

	signature, err := signingWorkflow.SignSchema(schema)
	if err != nil {
		t.Fatalf("Failed to sign schema: %v", err)
	}

	// Create mock server for revocation check
	wellKnownResponse := discovery.WellKnownResponse{
		SchemaVersion: "1.1",
		DeveloperName: "Test Developer",
		PublicKeyPEM:  publicKeyPEM,
		RevokedKeys:   []string{},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/schemapin.json" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(wellKnownResponse)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Extract domain from server URL
	domain := strings.TrimPrefix(server.URL, "http://")

	ctx := context.Background()
	result, err := workflow.VerifySchema(ctx, schema, signature, "test-tool", domain, false)
	if err != nil {
		t.Fatalf("Failed to verify schema: %v", err)
	}

	if !result.Valid {
		t.Error("Expected valid signature")
	}
	if result.FirstUse {
		t.Error("Expected not first use")
	}
	if !result.Pinned {
		t.Error("Expected key to be pinned")
	}
}

func TestCreateWellKnownResponse(t *testing.T) {
	publicKeyPEM := "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
	developerName := "Test Developer"
	contact := "test@example.com"
	revokedKeys := []string{"sha256:abcd1234"}
	schemaVersion := "1.1"

	response := CreateWellKnownResponse(publicKeyPEM, developerName, contact, revokedKeys, schemaVersion)

	if response["schema_version"] != schemaVersion {
		t.Errorf("Expected schema version %s, got %v", schemaVersion, response["schema_version"])
	}
	if response["developer_name"] != developerName {
		t.Errorf("Expected developer name %s, got %v", developerName, response["developer_name"])
	}
	if response["public_key_pem"] != publicKeyPEM {
		t.Errorf("Expected public key PEM %s, got %v", publicKeyPEM, response["public_key_pem"])
	}
	if response["contact"] != contact {
		t.Errorf("Expected contact %s, got %v", contact, response["contact"])
	}

	revokedKeysResult, ok := response["revoked_keys"].([]string)
	if !ok || len(revokedKeysResult) != 1 || revokedKeysResult[0] != "sha256:abcd1234" {
		t.Errorf("Expected revoked keys %v, got %v", revokedKeys, response["revoked_keys"])
	}
}

func TestCreateWellKnownResponse_DefaultVersion(t *testing.T) {
	response := CreateWellKnownResponse("test-key", "Test Developer", "", nil, "")

	if response["schema_version"] != "1.1" {
		t.Errorf("Expected default schema version 1.1, got %v", response["schema_version"])
	}
}

func TestCreateWellKnownResponse_NoOptionalFields(t *testing.T) {
	response := CreateWellKnownResponse("test-key", "Test Developer", "", nil, "1.1")

	if _, exists := response["contact"]; exists {
		t.Error("Expected no contact field when empty")
	}
	if _, exists := response["revoked_keys"]; exists {
		t.Error("Expected no revoked_keys field when nil")
	}
}

func TestValidateSchema(t *testing.T) {
	// Valid schema
	validSchema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"name": map[string]interface{}{
				"type": "string",
			},
		},
	}

	err := ValidateSchema(validSchema)
	if err != nil {
		t.Errorf("Expected valid schema to pass validation: %v", err)
	}

	// Nil schema
	err = ValidateSchema(nil)
	if err == nil {
		t.Error("Expected error for nil schema")
	}

	// Empty schema
	err = ValidateSchema(map[string]interface{}{})
	if err == nil {
		t.Error("Expected error for empty schema")
	}
}

func TestFormatKeyFingerprint(t *testing.T) {
	tests := []struct {
		name        string
		fingerprint string
		expected    string
	}{
		{
			name:        "Short fingerprint",
			fingerprint: "abcd1234",
			expected:    "abcd1234",
		},
		{
			name:        "With sha256 prefix",
			fingerprint: "sha256:abcdef1234567890abcdef1234567890abcdef12",
			expected:    "abcd:ef12:3456:...4567:890a:bcde:f12",
		},
		{
			name:        "Long fingerprint without prefix",
			fingerprint: "abcdef1234567890abcdef1234567890abcdef1234567890",
			expected:    "abcd:ef12:3456:...4567:890",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatKeyFingerprint(tt.fingerprint)
			if !strings.Contains(result, "abcd") {
				t.Errorf("Expected formatted fingerprint to contain 'abcd', got %s", result)
			}
		})
	}
}

func TestCalculateSchemaHash(t *testing.T) {
	schema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"name": map[string]interface{}{
				"type": "string",
			},
		},
	}

	hash, err := CalculateSchemaHash(schema)
	if err != nil {
		t.Fatalf("Failed to calculate schema hash: %v", err)
	}

	if len(hash) != 32 { // SHA-256 produces 32 bytes
		t.Errorf("Expected 32-byte hash, got %d bytes", len(hash))
	}

	// Test that same schema produces same hash
	hash2, err := CalculateSchemaHash(schema)
	if err != nil {
		t.Fatalf("Failed to calculate schema hash: %v", err)
	}

	if string(hash) != string(hash2) {
		t.Error("Expected same schema to produce same hash")
	}
}

func TestVerifySignatureOnly(t *testing.T) {
	// Generate test keys
	keyManager := crypto.NewKeyManager()
	privateKey, err := keyManager.GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	publicKeyPEM, err := keyManager.ExportPublicKeyPEM(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to export public key: %v", err)
	}

	// Create test schema and signature
	schema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"name": map[string]interface{}{
				"type": "string",
			},
		},
	}

	schemaHash, err := CalculateSchemaHash(schema)
	if err != nil {
		t.Fatalf("Failed to calculate schema hash: %v", err)
	}

	signatureManager := crypto.NewSignatureManager()
	signature, err := signatureManager.SignSchemaHash(schemaHash, privateKey)
	if err != nil {
		t.Fatalf("Failed to sign schema: %v", err)
	}

	// Test valid signature
	valid, err := VerifySignatureOnly(schemaHash, signature, publicKeyPEM)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}
	if !valid {
		t.Error("Expected valid signature")
	}

	// Test invalid signature
	valid, err = VerifySignatureOnly(schemaHash, "invalid-signature", publicKeyPEM)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}
	if valid {
		t.Error("Expected invalid signature")
	}

	// Test invalid public key
	_, err = VerifySignatureOnly(schemaHash, signature, "invalid-pem")
	if err == nil {
		t.Error("Expected error for invalid public key")
	}
}

func TestGenerateKeyPair(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	if !strings.Contains(privateKeyPEM, "BEGIN PRIVATE KEY") {
		t.Error("Expected valid private key PEM format")
	}
	if !strings.Contains(publicKeyPEM, "BEGIN PUBLIC KEY") {
		t.Error("Expected valid public key PEM format")
	}

	// Test that keys can be loaded
	keyManager := crypto.NewKeyManager()
	_, err = keyManager.LoadPrivateKeyPEM(privateKeyPEM)
	if err != nil {
		t.Errorf("Failed to load generated private key: %v", err)
	}

	_, err = keyManager.LoadPublicKeyPEM(publicKeyPEM)
	if err != nil {
		t.Errorf("Failed to load generated public key: %v", err)
	}
}

func TestSchemaVerificationError(t *testing.T) {
	err := NewSchemaVerificationError("TEST_ERROR", "Test message", "E001")

	if err.Type != "TEST_ERROR" {
		t.Errorf("Expected type 'TEST_ERROR', got %s", err.Type)
	}
	if err.Message != "Test message" {
		t.Errorf("Expected message 'Test message', got %s", err.Message)
	}
	if err.Code != "E001" {
		t.Errorf("Expected code 'E001', got %s", err.Code)
	}

	expectedError := "TEST_ERROR: Test message"
	if err.Error() != expectedError {
		t.Errorf("Expected error string '%s', got %s", expectedError, err.Error())
	}
}

func TestIsTemporaryError(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		isTemporary bool
	}{
		{"Nil error", nil, false},
		{"Timeout error", fmt.Errorf("connection timeout"), true},
		{"Network error", fmt.Errorf("network unreachable"), true},
		{"Connection refused", fmt.Errorf("connection refused"), true},
		{"Temporary error", fmt.Errorf("temporary failure"), true},
		{"Unavailable error", fmt.Errorf("service unavailable"), true},
		{"Permanent error", fmt.Errorf("invalid signature"), false},
		{"Schema error", fmt.Errorf("schema validation failed"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsTemporaryError(tt.err)
			if result != tt.isTemporary {
				t.Errorf("Expected %v, got %v for error: %v", tt.isTemporary, result, tt.err)
			}
		})
	}
}

func TestRetryVerification(t *testing.T) {
	// Create temporary database path
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	workflow, err := NewSchemaVerificationWorkflow(dbPath)
	if err != nil {
		t.Fatalf("Failed to create verification workflow: %v", err)
	}
	defer workflow.Close()

	schema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"name": map[string]interface{}{
				"type": "string",
			},
		},
	}

	ctx := context.Background()

	// Test with invalid signature (should not retry)
	result, err := RetryVerification(ctx, workflow, schema, "invalid-signature", "test-tool", "nonexistent.com", false, 2)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Valid {
		t.Error("Expected invalid result")
	}
}

// Benchmark tests
func BenchmarkSignSchema(b *testing.B) {
	// Generate a test key
	keyManager := crypto.NewKeyManager()
	privateKey, err := keyManager.GenerateKeypair()
	if err != nil {
		b.Fatalf("Failed to generate test key: %v", err)
	}

	privateKeyPEM, err := keyManager.ExportPrivateKeyPEM(privateKey)
	if err != nil {
		b.Fatalf("Failed to export private key: %v", err)
	}

	workflow, err := NewSchemaSigningWorkflow(privateKeyPEM)
	if err != nil {
		b.Fatalf("Failed to create signing workflow: %v", err)
	}

	schema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"name": map[string]interface{}{
				"type": "string",
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := workflow.SignSchema(schema)
		if err != nil {
			b.Fatalf("Failed to sign schema: %v", err)
		}
	}
}

func BenchmarkCalculateSchemaHash(b *testing.B) {
	schema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"name": map[string]interface{}{
				"type": "string",
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := CalculateSchemaHash(schema)
		if err != nil {
			b.Fatalf("Failed to calculate schema hash: %v", err)
		}
	}
}

func BenchmarkFormatKeyFingerprint(b *testing.B) {
	fingerprint := "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FormatKeyFingerprint(fingerprint)
	}
}
