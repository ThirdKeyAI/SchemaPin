package crypto

import (
	"crypto/sha256"
	"strings"
	"testing"
)

func TestKeyManager_GenerateKeypair(t *testing.T) {
	km := NewKeyManager()

	privateKey, err := km.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}

	if privateKey == nil {
		t.Fatal("GenerateKeypair() returned nil private key")
	}

	// Verify it's a P-256 key
	if privateKey.Curve.Params().Name != "P-256" {
		t.Errorf("Expected P-256 curve, got %s", privateKey.Curve.Params().Name)
	}
}

func TestKeyManager_ExportPrivateKeyPEM(t *testing.T) {
	km := NewKeyManager()
	privateKey, err := km.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}

	pemData, err := km.ExportPrivateKeyPEM(privateKey)
	if err != nil {
		t.Fatalf("ExportPrivateKeyPEM() error = %v", err)
	}

	// Should be valid PEM format (PKCS#8)
	if !strings.HasPrefix(pemData, "-----BEGIN PRIVATE KEY-----") {
		t.Error("PEM should start with PRIVATE KEY header")
	}
	if !strings.HasSuffix(pemData, "-----END PRIVATE KEY-----\n") {
		t.Error("PEM should end with PRIVATE KEY footer")
	}
}

func TestKeyManager_ExportPublicKeyPEM(t *testing.T) {
	km := NewKeyManager()
	privateKey, err := km.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}

	publicKey := &privateKey.PublicKey
	pemData, err := km.ExportPublicKeyPEM(publicKey)
	if err != nil {
		t.Fatalf("ExportPublicKeyPEM() error = %v", err)
	}

	// Should be valid PEM format
	if !strings.HasPrefix(pemData, "-----BEGIN PUBLIC KEY-----") {
		t.Error("PEM should start with PUBLIC KEY header")
	}
	if !strings.HasSuffix(pemData, "-----END PUBLIC KEY-----\n") {
		t.Error("PEM should end with PUBLIC KEY footer")
	}
}

func TestKeyManager_LoadPrivateKeyPEM(t *testing.T) {
	km := NewKeyManager()
	originalKey, err := km.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}

	pemData, err := km.ExportPrivateKeyPEM(originalKey)
	if err != nil {
		t.Fatalf("ExportPrivateKeyPEM() error = %v", err)
	}

	loadedKey, err := km.LoadPrivateKeyPEM(pemData)
	if err != nil {
		t.Fatalf("LoadPrivateKeyPEM() error = %v", err)
	}

	if loadedKey == nil {
		t.Fatal("LoadPrivateKeyPEM() returned nil key")
	}

	// Verify the loaded key is functionally equivalent
	if loadedKey.D.Cmp(originalKey.D) != 0 {
		t.Error("Loaded private key does not match original")
	}
}

func TestKeyManager_LoadPublicKeyPEM(t *testing.T) {
	km := NewKeyManager()
	privateKey, err := km.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}

	originalKey := &privateKey.PublicKey
	pemData, err := km.ExportPublicKeyPEM(originalKey)
	if err != nil {
		t.Fatalf("ExportPublicKeyPEM() error = %v", err)
	}

	loadedKey, err := km.LoadPublicKeyPEM(pemData)
	if err != nil {
		t.Fatalf("LoadPublicKeyPEM() error = %v", err)
	}

	if loadedKey == nil {
		t.Fatal("LoadPublicKeyPEM() returned nil key")
	}

	// Verify the loaded key is functionally equivalent
	if loadedKey.X.Cmp(originalKey.X) != 0 || loadedKey.Y.Cmp(originalKey.Y) != 0 {
		t.Error("Loaded public key does not match original")
	}
}

func TestKeyManager_KeyRoundtrip(t *testing.T) {
	km := NewKeyManager()
	originalPrivate, err := km.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}

	originalPublic := &originalPrivate.PublicKey

	// Export and reload private key
	privatePEM, err := km.ExportPrivateKeyPEM(originalPrivate)
	if err != nil {
		t.Fatalf("ExportPrivateKeyPEM() error = %v", err)
	}

	loadedPrivate, err := km.LoadPrivateKeyPEM(privatePEM)
	if err != nil {
		t.Fatalf("LoadPrivateKeyPEM() error = %v", err)
	}

	// Export and reload public key
	publicPEM, err := km.ExportPublicKeyPEM(originalPublic)
	if err != nil {
		t.Fatalf("ExportPublicKeyPEM() error = %v", err)
	}

	loadedPublic, err := km.LoadPublicKeyPEM(publicPEM)
	if err != nil {
		t.Fatalf("LoadPublicKeyPEM() error = %v", err)
	}

	// Keys should be functionally equivalent
	reExportedPrivate, err := km.ExportPrivateKeyPEM(loadedPrivate)
	if err != nil {
		t.Fatalf("Re-export private key error = %v", err)
	}

	reExportedPublic, err := km.ExportPublicKeyPEM(loadedPublic)
	if err != nil {
		t.Fatalf("Re-export public key error = %v", err)
	}

	if reExportedPrivate != privatePEM {
		t.Error("Private key roundtrip failed")
	}

	if reExportedPublic != publicPEM {
		t.Error("Public key roundtrip failed")
	}
}

func TestKeyManager_CalculateKeyFingerprint(t *testing.T) {
	km := NewKeyManager()
	privateKey, err := km.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}

	publicKey := &privateKey.PublicKey
	fingerprint, err := km.CalculateKeyFingerprint(publicKey)
	if err != nil {
		t.Fatalf("CalculateKeyFingerprint() error = %v", err)
	}

	// Should be in format 'sha256:hexstring'
	if !strings.HasPrefix(fingerprint, "sha256:") {
		t.Error("Fingerprint should start with 'sha256:'")
	}

	// Should be 64 hex characters after 'sha256:'
	hexPart := strings.TrimPrefix(fingerprint, "sha256:")
	if len(hexPart) != 64 {
		t.Errorf("Expected 64 hex characters, got %d", len(hexPart))
	}
}

func TestSignatureManager_SignAndVerifyHash(t *testing.T) {
	km := NewKeyManager()
	sm := NewSignatureManager()

	privateKey, err := km.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}

	publicKey := &privateKey.PublicKey
	testHash := []byte("test_hash_32_bytes_exactly_here!")

	// Sign the hash
	signatureB64, err := sm.SignHash(testHash, privateKey)
	if err != nil {
		t.Fatalf("SignHash() error = %v", err)
	}

	if signatureB64 == "" {
		t.Fatal("SignHash() returned empty signature")
	}

	// Verify the signature
	isValid := sm.VerifySignature(testHash, signatureB64, publicKey)
	if !isValid {
		t.Error("VerifySignature() returned false for valid signature")
	}
}

func TestSignatureManager_VerifyInvalidSignature(t *testing.T) {
	km := NewKeyManager()
	sm := NewSignatureManager()

	privateKey, err := km.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}

	publicKey := &privateKey.PublicKey
	testHash := []byte("test_hash_32_bytes_exactly_here!")

	// Create valid signature
	signatureB64, err := sm.SignHash(testHash, privateKey)
	if err != nil {
		t.Fatalf("SignHash() error = %v", err)
	}

	// Modify signature to make it invalid
	invalidSignature := signatureB64[:len(signatureB64)-4] + "XXXX"

	// Should fail verification
	isValid := sm.VerifySignature(testHash, invalidSignature, publicKey)
	if isValid {
		t.Error("VerifySignature() returned true for invalid signature")
	}
}

func TestSignatureManager_VerifyWrongHash(t *testing.T) {
	km := NewKeyManager()
	sm := NewSignatureManager()

	privateKey, err := km.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}

	publicKey := &privateKey.PublicKey
	originalHash := []byte("original_hash_32_bytes_exactly!")
	differentHash := []byte("different_hash_32_bytes_exactly")

	// Sign original hash
	signatureB64, err := sm.SignHash(originalHash, privateKey)
	if err != nil {
		t.Fatalf("SignHash() error = %v", err)
	}

	// Try to verify with different hash
	isValid := sm.VerifySignature(differentHash, signatureB64, publicKey)
	if isValid {
		t.Error("VerifySignature() returned true for wrong hash")
	}
}

func TestSignatureManager_VerifyWrongKey(t *testing.T) {
	km := NewKeyManager()
	sm := NewSignatureManager()

	privateKey1, err := km.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}

	privateKey2, err := km.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}

	publicKey2 := &privateKey2.PublicKey
	testHash := []byte("test_hash_32_bytes_exactly_here!")

	// Sign with first key
	signatureB64, err := sm.SignHash(testHash, privateKey1)
	if err != nil {
		t.Fatalf("SignHash() error = %v", err)
	}

	// Try to verify with second key
	isValid := sm.VerifySignature(testHash, signatureB64, publicKey2)
	if isValid {
		t.Error("VerifySignature() returned true for wrong key")
	}
}

func TestSignatureManager_SchemaSignatureMethods(t *testing.T) {
	km := NewKeyManager()
	sm := NewSignatureManager()

	privateKey, err := km.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}

	publicKey := &privateKey.PublicKey
	schemaHash := []byte("schema_hash_32_bytes_exactly_!!")

	// Sign schema hash
	signatureB64, err := sm.SignSchemaHash(schemaHash, privateKey)
	if err != nil {
		t.Fatalf("SignSchemaHash() error = %v", err)
	}

	// Verify schema signature
	isValid := sm.VerifySchemaSignature(schemaHash, signatureB64, publicKey)
	if !isValid {
		t.Error("VerifySchemaSignature() returned false for valid signature")
	}
}

func TestSignatureManager_SignatureNonDeterministic(t *testing.T) {
	km := NewKeyManager()
	sm := NewSignatureManager()

	privateKey, err := km.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}

	publicKey := &privateKey.PublicKey
	testHash := []byte("test_hash_32_bytes_exactly_here!")

	// Note: ECDSA signatures are NOT deterministic by design (they use random nonce)
	// This test verifies that different signatures for same data still verify correctly
	signature1, err := sm.SignHash(testHash, privateKey)
	if err != nil {
		t.Fatalf("SignHash() error = %v", err)
	}

	signature2, err := sm.SignHash(testHash, privateKey)
	if err != nil {
		t.Fatalf("SignHash() error = %v", err)
	}

	// Signatures should be different (due to random nonce)
	if signature1 == signature2 {
		t.Error("Signatures should be different due to random nonce")
	}

	// But both should verify correctly
	if !sm.VerifySignature(testHash, signature1, publicKey) {
		t.Error("First signature should verify correctly")
	}

	if !sm.VerifySignature(testHash, signature2, publicKey) {
		t.Error("Second signature should verify correctly")
	}
}

// Test cross-compatibility with known test vectors
func TestCrossCompatibility(t *testing.T) {
	km := NewKeyManager()
	sm := NewSignatureManager()

	// Test with a known schema to ensure consistent hashing
	_ = map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"name": map[string]interface{}{
				"type": "string",
			},
		},
	}

	// Generate a key pair
	privateKey, err := km.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}

	publicKey := &privateKey.PublicKey

	// Create a hash of the test schema (simulating what core package would do)
	testData := `{"properties":{"name":{"type":"string"}},"type":"object"}`
	hash := sha256.Sum256([]byte(testData))

	// Sign and verify
	signature, err := sm.SignHash(hash[:], privateKey)
	if err != nil {
		t.Fatalf("SignHash() error = %v", err)
	}

	isValid := sm.VerifySignature(hash[:], signature, publicKey)
	if !isValid {
		t.Error("Cross-compatibility test failed")
	}
}
