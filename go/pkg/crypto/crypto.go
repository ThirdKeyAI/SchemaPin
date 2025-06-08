// Package crypto provides ECDSA key management and signature operations for SchemaPin.
package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
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

// ExportPrivateKeyPEM exports private key to PEM format
func (k *KeyManager) ExportPrivateKeyPEM(key *ecdsa.PrivateKey) (string, error) {
	// TODO: Implement PKCS#8 private key export
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key: %w", err)
	}

	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
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
	return fmt.Sprintf("%x", hash), nil
}

// SignatureManager handles signature operations
type SignatureManager struct{}

// NewSignatureManager creates a new SignatureManager instance
func NewSignatureManager() *SignatureManager {
	return &SignatureManager{}
}

// SignHash signs a hash with the private key and returns base64-encoded signature
func (s *SignatureManager) SignHash(hashBytes []byte, privateKey *ecdsa.PrivateKey) (string, error) {
	r, sig, err := ecdsa.Sign(rand.Reader, privateKey, hashBytes)
	if err != nil {
		return "", fmt.Errorf("failed to sign hash: %w", err)
	}

	// TODO: Implement proper ASN.1 DER encoding for cross-language compatibility
	signature := append(r.Bytes(), sig.Bytes()...)
	return base64.StdEncoding.EncodeToString(signature), nil
}

// VerifySignature verifies a base64-encoded signature against a hash
func (s *SignatureManager) VerifySignature(hashBytes []byte, signatureB64 string, publicKey *ecdsa.PublicKey) bool {
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false
	}

	// TODO: Implement proper ASN.1 DER decoding for cross-language compatibility
	if len(signature) != 64 { // P-256 signature is 64 bytes (32+32)
		return false
	}

	r := new(big.Int).SetBytes(signature[:32])
	sig := new(big.Int).SetBytes(signature[32:])

	return ecdsa.Verify(publicKey, hashBytes, r, sig)
}

// SignSchemaHash signs a schema hash (convenience method)
func (s *SignatureManager) SignSchemaHash(schemaHash []byte, privateKey *ecdsa.PrivateKey) (string, error) {
	return s.SignHash(schemaHash, privateKey)
}

// VerifySchemaSignature verifies a schema signature (convenience method)
func (s *SignatureManager) VerifySchemaSignature(schemaHash []byte, signatureB64 string, publicKey *ecdsa.PublicKey) bool {
	return s.VerifySignature(schemaHash, signatureB64, publicKey)
}
