package pkg

import (
	"testing"

	"github.com/ThirdKeyAi/schemapin/go/pkg/core"
	"github.com/ThirdKeyAi/schemapin/go/pkg/crypto"
)

// TestFullIntegration demonstrates the complete SchemaPin workflow
func TestFullIntegration(t *testing.T) {
	// Initialize components
	km := crypto.NewKeyManager()
	sm := crypto.NewSignatureManager()
	schemaPinCore := core.NewSchemaPinCore()

	// Step 1: Generate a key pair
	privateKey, err := km.GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	publicKey := &privateKey.PublicKey

	// Step 2: Create a test schema
	schema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"name": map[string]interface{}{
				"type": "string",
			},
			"age": map[string]interface{}{
				"type":    "integer",
				"minimum": 0,
			},
		},
		"required": []interface{}{"name"},
	}

	// Step 3: Canonicalize the schema
	canonical, err := schemaPinCore.CanonicalizeSchema(schema)
	if err != nil {
		t.Fatalf("Failed to canonicalize schema: %v", err)
	}

	t.Logf("Canonical schema: %s", canonical)

	// Step 4: Hash the canonical schema
	schemaHash := schemaPinCore.HashCanonical(canonical)
	t.Logf("Schema hash length: %d bytes", len(schemaHash))

	// Step 5: Sign the schema hash
	signature, err := sm.SignSchemaHash(schemaHash, privateKey)
	if err != nil {
		t.Fatalf("Failed to sign schema hash: %v", err)
	}

	t.Logf("Signature: %s", signature)

	// Step 6: Verify the signature
	isValid := sm.VerifySchemaSignature(schemaHash, signature, publicKey)
	if !isValid {
		t.Fatal("Signature verification failed")
	}

	t.Log("Signature verification successful")

	// Step 7: Export keys to PEM format
	privatePEM, err := km.ExportPrivateKeyPEM(privateKey)
	if err != nil {
		t.Fatalf("Failed to export private key: %v", err)
	}

	publicPEM, err := km.ExportPublicKeyPEM(publicKey)
	if err != nil {
		t.Fatalf("Failed to export public key: %v", err)
	}

	t.Logf("Private key PEM length: %d", len(privatePEM))
	t.Logf("Public key PEM length: %d", len(publicPEM))

	// Step 8: Calculate key fingerprint
	fingerprint, err := km.CalculateKeyFingerprint(publicKey)
	if err != nil {
		t.Fatalf("Failed to calculate fingerprint: %v", err)
	}

	t.Logf("Key fingerprint: %s", fingerprint)

	// Step 9: Test key roundtrip
	loadedPrivate, err := km.LoadPrivateKeyPEM(privatePEM)
	if err != nil {
		t.Fatalf("Failed to load private key: %v", err)
	}

	loadedPublic, err := km.LoadPublicKeyPEM(publicPEM)
	if err != nil {
		t.Fatalf("Failed to load public key: %v", err)
	}

	// Step 10: Verify loaded keys work
	signature2, err := sm.SignSchemaHash(schemaHash, loadedPrivate)
	if err != nil {
		t.Fatalf("Failed to sign with loaded private key: %v", err)
	}

	isValid2 := sm.VerifySchemaSignature(schemaHash, signature2, loadedPublic)
	if !isValid2 {
		t.Fatal("Signature verification with loaded keys failed")
	}

	t.Log("Key roundtrip test successful")

	// Step 11: Test that different schemas produce different hashes
	differentSchema := map[string]interface{}{
		"type": "string",
	}

	differentCanonical, err := schemaPinCore.CanonicalizeSchema(differentSchema)
	if err != nil {
		t.Fatalf("Failed to canonicalize different schema: %v", err)
	}

	differentHash := schemaPinCore.HashCanonical(differentCanonical)

	// Hashes should be different
	hashesEqual := true
	for i := 0; i < len(schemaHash); i++ {
		if schemaHash[i] != differentHash[i] {
			hashesEqual = false
			break
		}
	}

	if hashesEqual {
		t.Fatal("Different schemas should produce different hashes")
	}

	t.Log("Different schema hash test successful")

	// Step 12: Test signature with wrong key fails
	wrongPrivate, err := km.GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate wrong key: %v", err)
	}

	wrongSignature, err := sm.SignSchemaHash(schemaHash, wrongPrivate)
	if err != nil {
		t.Fatalf("Failed to sign with wrong key: %v", err)
	}

	isValidWrong := sm.VerifySchemaSignature(schemaHash, wrongSignature, publicKey)
	if isValidWrong {
		t.Fatal("Signature with wrong key should not verify")
	}

	t.Log("Wrong key test successful")

	t.Log("Full integration test completed successfully")
}

// TestSchemaSigningWorkflow demonstrates a complete schema signing workflow
func TestSchemaSigningWorkflow(t *testing.T) {
	// This test simulates the workflow of a tool developer signing their schema
	// and a client verifying the signature

	km := crypto.NewKeyManager()
	sm := crypto.NewSignatureManager()
	schemaPinCore := core.NewSchemaPinCore()

	// Tool developer generates keys
	developerPrivate, err := km.GenerateKeypair()
	if err != nil {
		t.Fatalf("Developer key generation failed: %v", err)
	}

	developerPublic := &developerPrivate.PublicKey

	// Tool developer creates their tool schema
	toolSchema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"query": map[string]interface{}{
				"type":        "string",
				"description": "Search query",
			},
			"limit": map[string]interface{}{
				"type":    "integer",
				"minimum": 1,
				"maximum": 100,
				"default": 10,
			},
		},
		"required": []interface{}{"query"},
	}

	// Developer signs the schema
	canonical, err := schemaPinCore.CanonicalizeSchema(toolSchema)
	if err != nil {
		t.Fatalf("Schema canonicalization failed: %v", err)
	}

	schemaHash := schemaPinCore.HashCanonical(canonical)
	signature, err := sm.SignSchemaHash(schemaHash, developerPrivate)
	if err != nil {
		t.Fatalf("Schema signing failed: %v", err)
	}

	// Developer exports public key for distribution
	publicKeyPEM, err := km.ExportPublicKeyPEM(developerPublic)
	if err != nil {
		t.Fatalf("Public key export failed: %v", err)
	}

	fingerprint, err := km.CalculateKeyFingerprint(developerPublic)
	if err != nil {
		t.Fatalf("Fingerprint calculation failed: %v", err)
	}

	t.Logf("Developer public key fingerprint: %s", fingerprint)

	// Client receives the schema, signature, and public key
	// Client verifies the signature
	clientKM := crypto.NewKeyManager()
	clientSM := crypto.NewSignatureManager()
	clientCore := core.NewSchemaPinCore()

	// Client loads the public key
	clientPublicKey, err := clientKM.LoadPublicKeyPEM(publicKeyPEM)
	if err != nil {
		t.Fatalf("Client failed to load public key: %v", err)
	}

	// Client canonicalizes the received schema
	clientCanonical, err := clientCore.CanonicalizeSchema(toolSchema)
	if err != nil {
		t.Fatalf("Client schema canonicalization failed: %v", err)
	}

	// Should match developer's canonical form
	if clientCanonical != canonical {
		t.Fatalf("Client canonical form doesn't match developer's")
	}

	// Client hashes the canonical schema
	clientHash := clientCore.HashCanonical(clientCanonical)

	// Should match developer's hash
	for i := 0; i < len(schemaHash); i++ {
		if clientHash[i] != schemaHash[i] {
			t.Fatalf("Client hash doesn't match developer's hash")
		}
	}

	// Client verifies the signature
	isValid := clientSM.VerifySchemaSignature(clientHash, signature, clientPublicKey)
	if !isValid {
		t.Fatal("Client signature verification failed")
	}

	t.Log("Schema signing workflow completed successfully")
}
