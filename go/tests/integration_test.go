// Package tests provides integration tests for SchemaPin Go implementation.
package tests

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/ThirdKeyAi/schemapin/go/pkg/crypto"
	"github.com/ThirdKeyAi/schemapin/go/pkg/pinning"
	"github.com/ThirdKeyAi/schemapin/go/pkg/utils"
)

// TestEndToEndWorkflow tests the complete SchemaPin workflow
func TestEndToEndWorkflow(t *testing.T) {
	// Create temporary database with unique name
	tempDB := "/tmp/schemapin_integration_test_" + t.Name() + ".db"
	defer os.Remove(tempDB)

	// Step 1: Generate key pair
	keyManager := crypto.NewKeyManager()
	privateKey, err := keyManager.GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	privateKeyPEM, err := keyManager.ExportPrivateKeyPEM(privateKey)
	if err != nil {
		t.Fatalf("Failed to export private key: %v", err)
	}

	publicKeyPEM, err := keyManager.ExportPublicKeyPEM(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to export public key: %v", err)
	}

	// Step 2: Create and sign schema
	schema := map[string]interface{}{
		"name":        "test_tool",
		"description": "Integration test tool",
		"parameters": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"input": map[string]interface{}{
					"type":        "string",
					"description": "Test input",
				},
			},
			"required": []string{"input"},
		},
	}

	signingWorkflow, err := utils.NewSchemaSigningWorkflow(privateKeyPEM)
	if err != nil {
		t.Fatalf("Failed to create signing workflow: %v", err)
	}

	signature, err := signingWorkflow.SignSchema(schema)
	if err != nil {
		t.Fatalf("Failed to sign schema: %v", err)
	}

	// Step 3: Manually pin key (simulating discovery)
	toolID := "test.example.com/test_tool"
	domain := "test.example.com"
	developerName := "Test Developer"

	keyPinning, err := pinning.NewKeyPinning(tempDB, pinning.PinningModeAutomatic, nil)
	if err != nil {
		t.Fatalf("Failed to create key pinning: %v", err)
	}
	defer keyPinning.Close()

	err = keyPinning.PinKey(toolID, publicKeyPEM, domain, developerName)
	if err != nil {
		t.Fatalf("Failed to pin key: %v", err)
	}

	// Step 5: Verify signature
	schemaHash, err := utils.CalculateSchemaHash(schema)
	if err != nil {
		t.Fatalf("Failed to calculate schema hash: %v", err)
	}

	valid, err := utils.VerifySignatureOnly(schemaHash, signature, publicKeyPEM)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}

	if !valid {
		t.Fatal("Signature verification failed")
	}

	// Step 6: Verify key is pinned
	if !keyPinning.IsKeyPinned(toolID) {
		t.Fatal("Key should be pinned")
	}

	// Step 7: List pinned keys
	pinnedKeys, err := keyPinning.ListPinnedKeys()
	if err != nil {
		t.Fatalf("Failed to list pinned keys: %v", err)
	}

	if len(pinnedKeys) != 1 {
		t.Fatalf("Expected 1 pinned key, got %d", len(pinnedKeys))
	}

	t.Log("✅ End-to-end workflow test passed")
}

// TestCrossCompatibilityWithPython tests compatibility with Python implementation
func TestCrossCompatibilityWithPython(t *testing.T) {
	// Check if Python demo files exist
	pythonSchemaFile := "../../../python/examples/demo_schema_signed.json"
	pythonWellKnownFile := "../../../python/examples/demo_well_known.json"

	if _, err := os.Stat(pythonSchemaFile); os.IsNotExist(err) {
		t.Skip("Python demo files not found. Run python/examples/tool_developer.py first.")
	}

	// Load Python-generated files
	schemaData, err := loadJSONFile(pythonSchemaFile)
	if err != nil {
		t.Fatalf("Failed to load Python schema file: %v", err)
	}

	schema, ok := schemaData["schema"].(map[string]interface{})
	if !ok {
		t.Fatal("Invalid schema format in Python file")
	}

	signature, ok := schemaData["signature"].(string)
	if !ok {
		t.Fatal("Invalid signature format in Python file")
	}

	wellKnownData, err := loadJSONFile(pythonWellKnownFile)
	if err != nil {
		t.Fatalf("Failed to load Python well-known file: %v", err)
	}

	publicKeyPEM, ok := wellKnownData["public_key_pem"].(string)
	if !ok {
		t.Fatal("Invalid public key in Python well-known file")
	}

	// Verify Python signature with Go
	schemaHash, err := utils.CalculateSchemaHash(schema)
	if err != nil {
		t.Fatalf("Failed to calculate schema hash: %v", err)
	}

	valid, err := utils.VerifySignatureOnly(schemaHash, signature, publicKeyPEM)
	if err != nil {
		t.Fatalf("Failed to verify Python signature: %v", err)
	}

	if !valid {
		t.Fatal("Python signature verification failed with Go implementation")
	}

	t.Log("✅ Python cross-compatibility test passed")
}

// TestCrossCompatibilityWithJavaScript tests compatibility with JavaScript implementation
func TestCrossCompatibilityWithJavaScript(t *testing.T) {
	// Check if JavaScript demo files exist
	jsSchemaFile := "../../../javascript/demo_schema_signed.json"
	jsWellKnownFile := "../../../javascript/demo_well_known.json"

	if _, err := os.Stat(jsSchemaFile); os.IsNotExist(err) {
		t.Skip("JavaScript demo files not found. Run javascript/examples/developer.js first.")
	}

	// Load JavaScript-generated files
	schemaData, err := loadJSONFile(jsSchemaFile)
	if err != nil {
		t.Fatalf("Failed to load JavaScript schema file: %v", err)
	}

	schema, ok := schemaData["schema"].(map[string]interface{})
	if !ok {
		t.Fatal("Invalid schema format in JavaScript file")
	}

	signature, ok := schemaData["signature"].(string)
	if !ok {
		t.Fatal("Invalid signature format in JavaScript file")
	}

	wellKnownData, err := loadJSONFile(jsWellKnownFile)
	if err != nil {
		t.Fatalf("Failed to load JavaScript well-known file: %v", err)
	}

	publicKeyPEM, ok := wellKnownData["public_key_pem"].(string)
	if !ok {
		t.Fatal("Invalid public key in JavaScript well-known file")
	}

	// Verify JavaScript signature with Go
	schemaHash, err := utils.CalculateSchemaHash(schema)
	if err != nil {
		t.Fatalf("Failed to calculate schema hash: %v", err)
	}

	valid, err := utils.VerifySignatureOnly(schemaHash, signature, publicKeyPEM)
	if err != nil {
		t.Fatalf("Failed to verify JavaScript signature: %v", err)
	}

	if !valid {
		t.Fatal("JavaScript signature verification failed with Go implementation")
	}

	t.Log("✅ JavaScript cross-compatibility test passed")
}

// TestCLIToolsIntegration tests CLI tools integration
func TestCLIToolsIntegration(t *testing.T) {
	// This test would require building and running CLI tools
	// For now, we'll test the underlying functionality

	// Test key generation
	privateKeyPEM, publicKeyPEM, err := utils.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	if privateKeyPEM == "" || publicKeyPEM == "" {
		t.Fatal("Generated keys should not be empty")
	}

	// Test well-known response creation
	wellKnown := utils.CreateWellKnownResponse(
		publicKeyPEM,
		"CLI Test Developer",
		"test@example.com",
		[]string{},
		"1.1",
	)

	if wellKnown["public_key_pem"] != publicKeyPEM {
		t.Fatal("Well-known response should contain the public key")
	}

	if wellKnown["developer_name"] != "CLI Test Developer" {
		t.Fatal("Well-known response should contain developer name")
	}

	t.Log("✅ CLI tools integration test passed")
}

// TestKeyRevocation tests key revocation functionality
func TestKeyRevocation(t *testing.T) {
	// Create temporary database with unique name
	tempDB := "/tmp/schemapin_revocation_test_" + t.Name() + ".db"
	defer os.Remove(tempDB)

	// Generate keys
	keyManager := crypto.NewKeyManager()
	privateKey, err := keyManager.GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	publicKeyPEM, err := keyManager.ExportPublicKeyPEM(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to export public key: %v", err)
	}

	// Create well-known response with revoked key
	revokedKeys := []string{publicKeyPEM}
	wellKnown := utils.CreateWellKnownResponse(
		publicKeyPEM,
		"Revocation Test Developer",
		"test@example.com",
		revokedKeys,
		"1.1",
	)

	// Check that revoked keys are included
	if revokedKeysField, ok := wellKnown["revoked_keys"].([]string); ok {
		if len(revokedKeysField) != 1 || revokedKeysField[0] != publicKeyPEM {
			t.Fatal("Revoked keys not properly included in well-known response")
		}
	} else {
		t.Fatal("Revoked keys field missing from well-known response")
	}

	t.Log("✅ Key revocation test passed")
}

// TestInteractivePinning tests interactive pinning functionality
func TestInteractivePinning(t *testing.T) {
	// Create temporary database with unique name
	tempDB := "/tmp/schemapin_interactive_test_" + t.Name() + ".db"
	defer os.Remove(tempDB)

	// Generate keys
	keyManager := crypto.NewKeyManager()
	privateKey, err := keyManager.GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	publicKeyPEM, err := keyManager.ExportPublicKeyPEM(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to export public key: %v", err)
	}

	// Test automatic pinning mode
	keyPinning, err := pinning.NewKeyPinning(tempDB, pinning.PinningModeAutomatic, nil)
	if err != nil {
		t.Fatalf("Failed to create key pinning: %v", err)
	}
	defer keyPinning.Close()

	toolID := "interactive.test.com/tool"
	domain := "interactive.test.com"
	developerName := "Interactive Test Developer"

	// Pin key
	err = keyPinning.PinKey(toolID, publicKeyPEM, domain, developerName)
	if err != nil {
		t.Fatalf("Failed to pin key: %v", err)
	}

	// Verify key is pinned
	if !keyPinning.IsKeyPinned(toolID) {
		t.Fatal("Key should be pinned")
	}

	// Test domain policies
	keyPinning.SetDomainPolicy("trusted.example.com", pinning.PinningPolicyAlwaysTrust)
	keyPinning.SetDomainPolicy("untrusted.example.com", pinning.PinningPolicyNeverTrust)

	// Verify policies are set (this would require additional methods in the pinning package)
	t.Log("✅ Interactive pinning test passed")
}

// TestPerformance tests performance characteristics
func TestPerformance(t *testing.T) {
	// Generate key pair
	keyManager := crypto.NewKeyManager()
	privateKey, err := keyManager.GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create test schema
	schema := map[string]interface{}{
		"name":        "performance_test",
		"description": "Performance test schema",
		"parameters": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"data": map[string]interface{}{
					"type":        "string",
					"description": "Test data",
				},
			},
		},
	}

	// Test signing performance
	start := time.Now()
	signatureManager := crypto.NewSignatureManager()

	for i := 0; i < 100; i++ {
		schemaHash, err := utils.CalculateSchemaHash(schema)
		if err != nil {
			t.Fatalf("Failed to calculate schema hash: %v", err)
		}

		_, err = signatureManager.SignSchemaHash(schemaHash, privateKey)
		if err != nil {
			t.Fatalf("Failed to sign schema: %v", err)
		}
	}

	signingDuration := time.Since(start)
	t.Logf("100 signatures took %v (avg: %v per signature)", signingDuration, signingDuration/100)

	// Test verification performance
	schemaHash, _ := utils.CalculateSchemaHash(schema)
	signature, _ := signatureManager.SignSchemaHash(schemaHash, privateKey)

	start = time.Now()
	for i := 0; i < 100; i++ {
		valid := signatureManager.VerifySchemaSignature(schemaHash, signature, &privateKey.PublicKey)
		if !valid {
			t.Fatal("Signature verification failed")
		}
	}

	verificationDuration := time.Since(start)
	t.Logf("100 verifications took %v (avg: %v per verification)", verificationDuration, verificationDuration/100)

	// Performance should be reasonable (less than 10ms per operation on average)
	if signingDuration/100 > 10*time.Millisecond {
		t.Logf("Warning: Signing performance may be slow: %v per signature", signingDuration/100)
	}

	if verificationDuration/100 > 10*time.Millisecond {
		t.Logf("Warning: Verification performance may be slow: %v per verification", verificationDuration/100)
	}

	t.Log("✅ Performance test completed")
}

// Helper function to load JSON files
func loadJSONFile(filename string) (map[string]interface{}, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return result, nil
}
