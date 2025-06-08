// Package crypto provides ECDSA key management and signature operations for SchemaPin.
package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
)

// KeyManager handles ECDSA key operations
type KeyManager struct{}

// NewKeyManager creates a new KeyManager instance
func NewKeyManager() *KeyManager {
	return &KeyManager{}
}

// GenerateKeypair generates a new ECDSA key pair using P-256 curve
func (k *KeyManager) GenerateKeypair() (*ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key pair: %w", err)
	}
	return privateKey, nil
}

// ExportPrivateKeyPEM exports private key to PEM format using PKCS#8
func (k *KeyManager) ExportPrivateKeyPEM(key *ecdsa.PrivateKey) (string, error) {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key: %w", err)
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}

	return string(pem.EncodeToMemory(block)), nil
}

// ExportPublicKeyPEM exports public key to PEM format
func (k *KeyManager) ExportPublicKeyPEM(key *ecdsa.PublicKey) (string, error) {
	keyBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: keyBytes,
	}

	return string(pem.EncodeToMemory(block)), nil
}

// LoadPrivateKeyPEM loads private key from PEM format
func (k *KeyManager) LoadPrivateKeyPEM(pemData string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try PKCS#8 format first (preferred)
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if ecdsaKey, ok := key.(*ecdsa.PrivateKey); ok {
			return ecdsaKey, nil
		}
		return nil, fmt.Errorf("not an ECDSA private key")
	}

	// Fall back to EC private key format
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return key, nil
}

// LoadPublicKeyPEM loads public key from PEM format
func (k *KeyManager) LoadPublicKeyPEM(pemData string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	ecdsaKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA public key")
	}

	return ecdsaKey, nil
}

// CalculateKeyFingerprint computes SHA-256 fingerprint of public key
func (k *KeyManager) CalculateKeyFingerprint(key *ecdsa.PublicKey) (string, error) {
	keyBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key for fingerprint: %w", err)
	}

	hash := sha256.Sum256(keyBytes)
	return fmt.Sprintf("sha256:%x", hash), nil
}

// CalculateKeyFingerprintFromPEM computes SHA-256 fingerprint from PEM-encoded public key
func (k *KeyManager) CalculateKeyFingerprintFromPEM(publicKeyPEM string) (string, error) {
	publicKey, err := k.LoadPublicKeyPEM(publicKeyPEM)
	if err != nil {
		return "", err
	}
	return k.CalculateKeyFingerprint(publicKey)
}

// SignatureManager handles signature operations
type SignatureManager struct{}

// NewSignatureManager creates a new SignatureManager instance
func NewSignatureManager() *SignatureManager {
	return &SignatureManager{}
}

// ecdsaSignature represents the ASN.1 structure for ECDSA signatures
type ecdsaSignature struct {
	R, S *big.Int
}

// SignHash signs a hash with the private key and returns base64-encoded signature
func (s *SignatureManager) SignHash(hashBytes []byte, privateKey *ecdsa.PrivateKey) (string, error) {
	r, sig, err := ecdsa.Sign(rand.Reader, privateKey, hashBytes)
	if err != nil {
		return "", fmt.Errorf("failed to sign hash: %w", err)
	}

	// Encode signature in ASN.1 DER format for cross-language compatibility
	signature := ecdsaSignature{R: r, S: sig}
	derBytes, err := asn1.Marshal(signature)
	if err != nil {
		return "", fmt.Errorf("failed to marshal signature: %w", err)
	}

	return base64.StdEncoding.EncodeToString(derBytes), nil
}

// VerifySignature verifies a base64-encoded signature against a hash
func (s *SignatureManager) VerifySignature(hashBytes []byte, signatureB64 string, publicKey *ecdsa.PublicKey) bool {
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false
	}

	// Decode ASN.1 DER signature
	var sig ecdsaSignature
	if _, err := asn1.Unmarshal(signature, &sig); err != nil {
		return false
	}

	return ecdsa.Verify(publicKey, hashBytes, sig.R, sig.S)
}

// SignSchemaHash signs a schema hash (convenience method)
func (s *SignatureManager) SignSchemaHash(schemaHash []byte, privateKey *ecdsa.PrivateKey) (string, error) {
	return s.SignHash(schemaHash, privateKey)
}

// VerifySchemaSignature verifies a schema signature (convenience method)
func (s *SignatureManager) VerifySchemaSignature(schemaHash []byte, signatureB64 string, publicKey *ecdsa.PublicKey) bool {
	return s.VerifySignature(schemaHash, signatureB64, publicKey)
}
