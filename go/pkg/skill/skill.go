// Package skill provides skill folder signing and verification for SchemaPin
// v1.3 with v1.4-alpha additions.
//
// Extends SchemaPin's ECDSA P-256 signing to cover file-based skill folders
// (AgentSkills spec). Same keys, same .well-known discovery, new canonicalization
// target.
//
// v1.4-alpha additions:
//   - Optional signature expiration (expires_at) on .schemapin.sig --
//     written via SignSkillWithOptions. Verifiers degrade past expires_at
//     instead of failing.
//   - Optional DNS TXT cross-verification via VerifySkillOfflineWithDNS;
//     see the dns subpackage for the parser and lookup helpers.
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

// Version constants written into the SchemapinVersion field of new
// signatures. v1.3 signatures lack expires_at; v1.4 signatures may carry
// it. Verifiers handle both transparently.
const (
	schemapinVersionV13 = "1.3"
	schemapinVersionV14 = "1.4"
)

// SkillSignature represents the JSON structure of a .schemapin.sig file.
//
// Optional v1.4 fields:
//   - ExpiresAt: when present, verifiers treat signatures past the expiration
//     as degraded (warning) rather than a hard failure -- see VerifySkillOffline.
//   - SchemaVersion: caller-supplied semver string identifying *this* version
//     of the signed artifact. Surfaced via VerificationResult for policy use.
//   - PreviousHash: sha256:<hex> of the prior signed version's SkillHash,
//     forming a hash chain. Pair with VerifyChain.
type SkillSignature struct {
	SchemapinVersion string            `json:"schemapin_version"`
	SkillName        string            `json:"skill_name"`
	SkillHash        string            `json:"skill_hash"`
	Signature        string            `json:"signature"`
	SignedAt         string            `json:"signed_at"`
	ExpiresAt        string            `json:"expires_at,omitempty"`
	SchemaVersion    string            `json:"schema_version,omitempty"`
	PreviousHash     string            `json:"previous_hash,omitempty"`
	Domain           string            `json:"domain"`
	SignerKid        string            `json:"signer_kid"`
	FileManifest     map[string]string `json:"file_manifest"`
}

// SignOptions are optional sign-time parameters for SignSkillWithOptions.
//
// All fields are optional and default to "absent": empty strings derive the
// value from the key/SKILL.md/dirname, and a zero ExpiresIn omits the
// expires_at field entirely.
type SignOptions struct {
	// SignerKid overrides the kid written into the signature. When empty,
	// the kid is derived from the public key fingerprint.
	SignerKid string
	// SkillName overrides the skill_name written into the signature. When
	// empty, it is parsed from SKILL.md frontmatter or falls back to the
	// directory basename.
	SkillName string
	// ExpiresIn sets a TTL relative to signing time. When > 0, the
	// signature carries an RFC 3339 expires_at field and the version is
	// bumped to "1.4". A zero value (the default) writes no expires_at and
	// keeps the version at "1.3".
	ExpiresIn time.Duration
	// SchemaVersion is a caller-supplied semver string identifying *this*
	// version of the signed artifact (v1.4 alpha.2). Empty omits the field.
	SchemaVersion string
	// PreviousHash is sha256:<hex> of the prior signed version's SkillHash,
	// forming a hash chain (v1.4 alpha.2). Pair with VerifyChain at verify
	// time. Empty omits the field.
	PreviousHash string
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
//
// Preserved as a thin wrapper over SignSkillWithOptions for backward
// compatibility with v1.3 callers.
func SignSkill(skillDir, privateKeyPEM, domain string, signerKid, skillName string) (*SkillSignature, error) {
	return SignSkillWithOptions(skillDir, privateKeyPEM, domain, SignOptions{
		SignerKid: signerKid,
		SkillName: skillName,
	})
}

// SignSkillWithOptions canonicalizes a skill directory, signs it, and writes
// .schemapin.sig. Mirrors the v1.4 Rust API sign_skill_with_options.
//
// When options.ExpiresIn > 0, an RFC 3339 expires_at timestamp is written
// (truncated to seconds, UTC, "Z" suffix) and the schemapin_version is
// bumped to "1.4". When ExpiresIn is zero, expires_at is omitted and the
// version stays at "1.3" -- bytewise-identical to the v1.3 wire format.
func SignSkillWithOptions(skillDir, privateKeyPEM, domain string, options SignOptions) (*SkillSignature, error) {
	keyManager := crypto.NewKeyManager()

	privateKey, err := keyManager.LoadPrivateKeyPEM(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	rootHash, manifest, err := CanonicalizeSkill(skillDir)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize skill: %w", err)
	}

	skillName := options.SkillName
	if skillName == "" {
		skillName = ParseSkillName(skillDir)
	}

	signerKid := options.SignerKid
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

	now := time.Now().UTC().Truncate(time.Second)
	expiresAt := ""
	if options.ExpiresIn > 0 {
		expiresAt = now.Add(options.ExpiresIn).UTC().Format(time.RFC3339)
	}

	// Any v1.4 optional field bumps the version stamp; pure v1.3 sigs stay
	// "1.3" for byte-stable backward compatibility.
	version := schemapinVersionV13
	if expiresAt != "" || options.SchemaVersion != "" || options.PreviousHash != "" {
		version = schemapinVersionV14
	}

	sig := &SkillSignature{
		SchemapinVersion: version,
		SkillName:        skillName,
		SkillHash:        fmt.Sprintf("sha256:%s", hex.EncodeToString(rootHash)),
		Signature:        signatureB64,
		SignedAt:         now.Format(time.RFC3339),
		ExpiresAt:        expiresAt,
		SchemaVersion:    options.SchemaVersion,
		PreviousHash:     options.PreviousHash,
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

	// v1.4: apply optional signature expiration check. No-op when ExpiresAt
	// is empty; otherwise may set Expired/ExpiresAt and append a warning.
	result = result.WithExpirationCheck(sig.ExpiresAt)
	// v1.4 alpha.2: surface lineage metadata (informational; chain enforcement
	// is opt-in via VerifyChain).
	return result.WithLineageMetadata(sig.SchemaVersion, sig.PreviousHash)
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

// ChainErrorKind enumerates VerifyChain failure modes.
type ChainErrorKind int

const (
	// ChainErrorNoPreviousHash indicates current.PreviousHash is empty.
	ChainErrorNoPreviousHash ChainErrorKind = iota + 1
	// ChainErrorMismatch indicates current.PreviousHash != previous.SkillHash.
	ChainErrorMismatch
)

// ChainError is returned by VerifyChain on lineage failure.
type ChainError struct {
	Kind     ChainErrorKind
	Expected string
	Got      string
}

func (e *ChainError) Error() string {
	switch e.Kind {
	case ChainErrorNoPreviousHash:
		return "current signature has no previous_hash field"
	case ChainErrorMismatch:
		return fmt.Sprintf(
			"previous_hash mismatch: current.previous_hash = %s, previous.skill_hash = %s",
			e.Got, e.Expected,
		)
	default:
		return "unknown chain error"
	}
}

// VerifyChain verifies that current is the legitimate successor of previous
// via the previous_hash lineage chain (v1.4 alpha.2).
//
// Checks current.PreviousHash == previous.SkillHash.
//
// This is a pure-metadata check -- no cryptography is re-evaluated. Both
// signatures must already be cryptographically verified separately via
// VerifySkillOffline for the chain check to be meaningful.
//
// Use this to defend against rug-pull attacks where an attacker substitutes
// a schema/skill out-of-band: a legitimate update declares the prior version's
// hash; an unauthorized substitution either omits previous_hash or points at
// a hash the verifier has not accepted as a valid ancestor.
func VerifyChain(current, previous *SkillSignature) error {
	if current.PreviousHash == "" {
		return &ChainError{Kind: ChainErrorNoPreviousHash}
	}
	if current.PreviousHash != previous.SkillHash {
		return &ChainError{
			Kind:     ChainErrorMismatch,
			Expected: previous.SkillHash,
			Got:      current.PreviousHash,
		}
	}
	return nil
}
