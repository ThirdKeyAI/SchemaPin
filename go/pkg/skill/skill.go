// Package skill provides skill folder signing and verification for SchemaPin v1.3.
//
// Extends SchemaPin's ECDSA P-256 signing to cover file-based skill folders
// (AgentSkills spec). Same keys, same .well-known discovery, new canonicalization
// target.
package skill

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ThirdKeyAi/schemapin/go/pkg/crypto"
	"github.com/ThirdKeyAi/schemapin/go/pkg/discovery"
	"github.com/ThirdKeyAi/schemapin/go/pkg/resolver"
	"github.com/ThirdKeyAi/schemapin/go/pkg/revocation"
	"github.com/ThirdKeyAi/schemapin/go/pkg/verification"
)

// SignatureFilename is the name of the signature file written into skill directories.
const SignatureFilename = ".schemapin.sig"

const schemapinVersion = "1.3"

// SkillSignature represents the JSON structure of a .schemapin.sig file.
type SkillSignature struct {
	SchemapinVersion string            `json:"schemapin_version"`
	SkillName        string            `json:"skill_name"`
	SkillHash        string            `json:"skill_hash"`
	Signature        string            `json:"signature"`
	SignedAt         string            `json:"signed_at"`
	Domain           string            `json:"domain"`
	SignerKid        string            `json:"signer_kid"`
	FileManifest     map[string]string `json:"file_manifest"`
}

// TamperedFiles holds the result of comparing two file manifests.
type TamperedFiles struct {
	Modified []string
	Added    []string
	Removed  []string
}

// walkSorted recursively walks a directory in sorted order, building the manifest.
func walkSorted(dir, baseDir string, manifest map[string]string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("failed to read directory %s: %w", dir, err)
	}

	// os.ReadDir returns entries sorted by name already, but let's be explicit
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	for _, entry := range entries {
		fullPath := filepath.Join(dir, entry.Name())

		// Check for symlinks using Lstat
		info, err := os.Lstat(fullPath)
		if err != nil {
			return fmt.Errorf("failed to stat %s: %w", fullPath, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			continue
		}

		if info.IsDir() {
			if err := walkSorted(fullPath, baseDir, manifest); err != nil {
				return err
			}
			continue
		}

		// Regular file
		if entry.Name() == SignatureFilename {
			continue
		}

		relPath, err := filepath.Rel(baseDir, fullPath)
		if err != nil {
			return fmt.Errorf("failed to compute relative path: %w", err)
		}
		// Normalize to forward slashes
		relStr := filepath.ToSlash(relPath)

		fileBytes, err := os.ReadFile(fullPath) // #nosec G304 -- path constructed from trusted directory walk
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", fullPath, err)
		}

		h := sha256.New()
		h.Write([]byte(relStr))
		h.Write(fileBytes)
		digest := hex.EncodeToString(h.Sum(nil))
		manifest[relStr] = "sha256:" + digest
	}

	return nil
}

// CanonicalizeSkill walks a skill directory deterministically and computes a root hash.
//
// Algorithm:
//  1. Recursive sorted directory walk
//  2. Skip .schemapin.sig and symlinks
//  3. Normalize paths to forward slashes
//  4. Per-file: SHA-256(relative_path_utf8 + file_bytes) -> hex -> "sha256:<hex>"
//  5. Root: sort manifest keys, extract hex digests, concatenate, SHA-256 -> raw bytes
//
// Returns (root_hash_bytes, manifest, error). Returns error if directory is empty.
func CanonicalizeSkill(skillDir string) ([]byte, map[string]string, error) {
	absDir, err := filepath.Abs(skillDir)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve skill directory: %w", err)
	}

	// Resolve any symlinks in the base directory itself
	absDir, err = filepath.EvalSymlinks(absDir)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to eval symlinks: %w", err)
	}

	manifest := make(map[string]string)
	if err := walkSorted(absDir, absDir, manifest); err != nil {
		return nil, nil, err
	}

	if len(manifest) == 0 {
		return nil, nil, fmt.Errorf("skill directory is empty or contains no signable files: %s", skillDir)
	}

	// Collect sorted keys
	keys := make([]string, 0, len(manifest))
	for k := range manifest {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Extract hex digests and concatenate
	var builder strings.Builder
	for _, k := range keys {
		val := manifest[k]
		// Split on ":" and take the hex part
		parts := strings.SplitN(val, ":", 2)
		if len(parts) == 2 {
			builder.WriteString(parts[1])
		}
	}

	rootHash := sha256.Sum256([]byte(builder.String()))
	return rootHash[:], manifest, nil
}

// ParseSkillName extracts the skill name from SKILL.md frontmatter.
// Falls back to the directory basename if SKILL.md is missing or has no name field.
func ParseSkillName(skillDir string) string {
	absDir, err := filepath.Abs(skillDir)
	if err != nil {
		return filepath.Base(skillDir)
	}

	skillMD := filepath.Join(absDir, "SKILL.md")
	data, err := os.ReadFile(skillMD) // #nosec G304 -- path constructed from user-provided skill directory
	if err != nil {
		return filepath.Base(absDir)
	}

	text := string(data)

	// Match frontmatter block: --- ... ---
	fmRe := regexp.MustCompile(`(?s)^---\s*\n(.*?)\n---`)
	fmMatch := fmRe.FindStringSubmatch(text)
	if fmMatch == nil {
		return filepath.Base(absDir)
	}

	frontmatter := fmMatch[1]

	// Match name: value in frontmatter (with optional quotes)
	nameRe := regexp.MustCompile(`(?m)^name:\s*['"]?([^'"#\n]+?)['"]?\s*$`)
	nameMatch := nameRe.FindStringSubmatch(frontmatter)
	if nameMatch == nil {
		return filepath.Base(absDir)
	}

	return strings.TrimSpace(nameMatch[1])
}

// LoadSignature reads and parses the .schemapin.sig file from a skill directory.
func LoadSignature(skillDir string) (*SkillSignature, error) {
	sigPath := filepath.Join(skillDir, SignatureFilename)
	data, err := os.ReadFile(sigPath) // #nosec G304 -- path constructed from user-provided skill directory
	if err != nil {
		return nil, fmt.Errorf("failed to read signature file: %w", err)
	}

	var sig SkillSignature
	if err := json.Unmarshal(data, &sig); err != nil {
		return nil, fmt.Errorf("failed to parse signature file: %w", err)
	}

	return &sig, nil
}

// SignSkill canonicalizes a skill directory, signs it, and writes .schemapin.sig.
//
// If signerKid is empty, it is auto-computed from the public key.
// If skillName is empty, it is parsed from SKILL.md (or falls back to dir name).
func SignSkill(skillDir, privateKeyPEM, domain string, signerKid, skillName string) (*SkillSignature, error) {
	keyManager := crypto.NewKeyManager()

	privateKey, err := keyManager.LoadPrivateKeyPEM(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	rootHash, manifest, err := CanonicalizeSkill(skillDir)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize skill: %w", err)
	}

	if skillName == "" {
		skillName = ParseSkillName(skillDir)
	}

	if signerKid == "" {
		publicKey := privateKey.Public().(*ecdsa.PublicKey)
		publicKeyPEM, err := keyManager.ExportPublicKeyPEM(publicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to export public key: %w", err)
		}
		signerKid, err = keyManager.CalculateKeyFingerprintFromPEM(publicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate fingerprint: %w", err)
		}
	}

	sigManager := crypto.NewSignatureManager()
	signatureB64, err := sigManager.SignHash(rootHash, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign hash: %w", err)
	}

	sig := &SkillSignature{
		SchemapinVersion: schemapinVersion,
		SkillName:        skillName,
		SkillHash:        fmt.Sprintf("sha256:%s", hex.EncodeToString(rootHash)),
		Signature:        signatureB64,
		SignedAt:         time.Now().UTC().Format(time.RFC3339),
		Domain:           domain,
		SignerKid:        signerKid,
		FileManifest:     manifest,
	}

	sigJSON, err := json.MarshalIndent(sig, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signature: %w", err)
	}

	sigPath := filepath.Join(skillDir, SignatureFilename)
	if err := os.WriteFile(sigPath, append(sigJSON, '\n'), 0600); err != nil { // #nosec G306
		return nil, fmt.Errorf("failed to write signature file: %w", err)
	}

	return sig, nil
}

// VerifySkillOffline verifies a signed skill folder offline using pre-fetched
// discovery and revocation data. Follows the 7-step verification flow.
func VerifySkillOffline(
	skillDir string,
	disc *discovery.WellKnownResponse,
	sig *SkillSignature,
	rev *revocation.RevocationDocument,
	pinStore *verification.KeyPinStore,
	toolID string,
) *verification.VerificationResult {
	// Step 1: Load signature if nil
	if sig == nil {
		var err error
		sig, err = LoadSignature(skillDir)
		if err != nil {
			return &verification.VerificationResult{
				Valid:        false,
				ErrorCode:    verification.ErrSignatureInvalid,
				ErrorMessage: "No .schemapin.sig found in skill directory",
			}
		}
	}

	domain := sig.Domain
	if toolID == "" {
		toolID = sig.SkillName
		if toolID == "" {
			toolID = filepath.Base(skillDir)
		}
	}

	// Step 2: Validate discovery document
	if disc == nil || disc.PublicKeyPEM == "" || !strings.Contains(disc.PublicKeyPEM, "-----BEGIN PUBLIC KEY-----") {
		return &verification.VerificationResult{
			Valid:        false,
			Domain:       domain,
			ErrorCode:    verification.ErrDiscoveryInvalid,
			ErrorMessage: "Discovery document missing or invalid public_key_pem",
		}
	}

	// Step 3: Extract public key and compute fingerprint
	keyManager := crypto.NewKeyManager()
	publicKey, err := keyManager.LoadPublicKeyPEM(disc.PublicKeyPEM)
	if err != nil {
		return &verification.VerificationResult{
			Valid:        false,
			Domain:       domain,
			ErrorCode:    verification.ErrKeyNotFound,
			ErrorMessage: fmt.Sprintf("Failed to load public key: %v", err),
		}
	}

	fingerprint, err := keyManager.CalculateKeyFingerprintFromPEM(disc.PublicKeyPEM)
	if err != nil {
		return &verification.VerificationResult{
			Valid:        false,
			Domain:       domain,
			ErrorCode:    verification.ErrKeyNotFound,
			ErrorMessage: fmt.Sprintf("Failed to calculate fingerprint: %v", err),
		}
	}

	// Step 4: Check revocation
	if err := revocation.CheckRevocationCombined(disc.RevokedKeys, rev, fingerprint); err != nil {
		return &verification.VerificationResult{
			Valid:        false,
			Domain:       domain,
			ErrorCode:    verification.ErrKeyRevoked,
			ErrorMessage: err.Error(),
		}
	}

	// Step 5: TOFU key pinning
	var pinResult verification.PinResult
	if pinStore != nil {
		pinResult = pinStore.CheckAndPin(toolID, domain, fingerprint)
		if pinResult == verification.PinChanged {
			return &verification.VerificationResult{
				Valid:        false,
				Domain:       domain,
				ErrorCode:    verification.ErrKeyPinMismatch,
				ErrorMessage: "Key fingerprint changed since last use",
			}
		}
	}

	// Step 6: Canonicalize and verify signature
	rootHash, _, err := CanonicalizeSkill(skillDir)
	if err != nil {
		return &verification.VerificationResult{
			Valid:        false,
			Domain:       domain,
			ErrorCode:    verification.ErrSchemaCanonicalizationFailed,
			ErrorMessage: fmt.Sprintf("Failed to canonicalize skill: %v", err),
		}
	}

	sigManager := crypto.NewSignatureManager()
	valid := sigManager.VerifySignature(rootHash, sig.Signature, publicKey)

	if !valid {
		return &verification.VerificationResult{
			Valid:        false,
			Domain:       domain,
			ErrorCode:    verification.ErrSignatureInvalid,
			ErrorMessage: "Signature verification failed",
		}
	}

	// Step 7: Return success
	result := &verification.VerificationResult{
		Valid:         true,
		Domain:        domain,
		DeveloperName: disc.DeveloperName,
		Warnings:      []string{},
	}

	if pinStore != nil {
		result.KeyPinning = &verification.KeyPinningStatus{
			Status: string(pinResult),
		}
	}

	return result
}

// VerifySkillWithResolver verifies a signed skill folder using a resolver
// for discovery and revocation.
func VerifySkillWithResolver(
	skillDir, domain string,
	r resolver.SchemaResolver,
	pinStore *verification.KeyPinStore,
	toolID string,
) *verification.VerificationResult {
	disc, err := r.ResolveDiscovery(domain)
	if err != nil {
		return &verification.VerificationResult{
			Valid:        false,
			Domain:       domain,
			ErrorCode:    verification.ErrDiscoveryFetchFailed,
			ErrorMessage: fmt.Sprintf("Could not resolve discovery for domain: %s", domain),
		}
	}

	rev, _ := r.ResolveRevocation(domain, disc)

	return VerifySkillOffline(skillDir, disc, nil, rev, pinStore, toolID)
}

// DetectTamperedFiles compares a current file manifest against a signed manifest.
// Returns a TamperedFiles struct with sorted Modified, Added, and Removed slices.
func DetectTamperedFiles(current, signed map[string]string) *TamperedFiles {
	result := &TamperedFiles{
		Modified: []string{},
		Added:    []string{},
		Removed:  []string{},
	}

	// Find added and modified
	for k, v := range current {
		if sv, ok := signed[k]; !ok {
			result.Added = append(result.Added, k)
		} else if v != sv {
			result.Modified = append(result.Modified, k)
		}
	}

	// Find removed
	for k := range signed {
		if _, ok := current[k]; !ok {
			result.Removed = append(result.Removed, k)
		}
	}

	sort.Strings(result.Modified)
	sort.Strings(result.Added)
	sort.Strings(result.Removed)

	return result
}
