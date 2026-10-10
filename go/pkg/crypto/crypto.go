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
		ecdsaKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an ECDSA private key")
		}
		if err := requireP256(ecdsaKey.Curve, "private key"); err != nil {
			return nil, err
		}
		return ecdsaKey, nil
	}

	// Fall back to EC private key format
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	if err := requireP256(key.Curve, "private key"); err != nil {
		return nil, err
	}

	return key, nil
}

// requireP256 enforces spec section 10: keys that are not ECDSA P-256 MUST be
// rejected.
func requireP256(curve elliptic.Curve, what string) error {
	if curve != elliptic.P256() {
		name := "unknown"
		if curve != nil && curve.Params() != nil {
			name = curve.Params().Name
		}
		return fmt.Errorf("%s uses curve %s; only P-256 is accepted", what, name)
	}
	return nil
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
	if err := requireP256(ecdsaKey.Curve, "public key"); err != nil {
		return nil, err
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

// SignHash signs data with ECDSA P-256 over SHA-256(hashBytes) and returns a
// base64-encoded DER signature.
//
// The ECDSA input is SHA-256(hashBytes): for schema and legacy skill
// signatures hashBytes is itself the canonical SHA-256 digest, for bundles and
// v1.4 skill signature documents it is the canonical bytes. This matches the
// Python (cryptography), JavaScript (createSign('SHA256')) and Rust (p256
// SigningKey::sign) SDKs, which all hash their input before ECDSA. Earlier Go
// releases passed hashBytes to ecdsa.Sign directly and were therefore
// incompatible with every other SDK.
func (s *SignatureManager) SignHash(hashBytes []byte, privateKey *ecdsa.PrivateKey) (string, error) {
	if privateKey == nil {
		return "", fmt.Errorf("private key is nil")
	}
	if err := requireP256(privateKey.Curve, "private key"); err != nil {
		return "", err
	}
	digest := sha256.Sum256(hashBytes)
	r, sig, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
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

// VerifySignature verifies a base64-encoded DER signature against
// SHA-256(hashBytes). See SignHash for the hashing convention. Trailing bytes
// after the DER structure, non-P-256 keys and malformed base64 all fail.
func (s *SignatureManager) VerifySignature(hashBytes []byte, signatureB64 string, publicKey *ecdsa.PublicKey) bool {
	if publicKey == nil || requireP256(publicKey.Curve, "public key") != nil {
		return false
	}
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false
	}

	// Decode ASN.1 DER signature; reject trailing garbage.
	var sig ecdsaSignature
	rest, err := asn1.Unmarshal(signature, &sig)
	if err != nil || len(rest) != 0 {
		return false
	}
	if sig.R == nil || sig.S == nil || sig.R.Sign() <= 0 || sig.S.Sign() <= 0 {
		return false
	}

	digest := sha256.Sum256(hashBytes)
	return ecdsa.Verify(publicKey, digest[:], sig.R, sig.S)
}

// SignSchemaHash signs a schema hash (convenience method)
func (s *SignatureManager) SignSchemaHash(schemaHash []byte, privateKey *ecdsa.PrivateKey) (string, error) {
	return s.SignHash(schemaHash, privateKey)
}

// VerifySchemaSignature verifies a schema signature (convenience method)
func (s *SignatureManager) VerifySchemaSignature(schemaHash []byte, signatureB64 string, publicKey *ecdsa.PublicKey) bool {
	return s.VerifySignature(schemaHash, signatureB64, publicKey)
}
