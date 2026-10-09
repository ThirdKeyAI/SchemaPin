// Package skill provides skill folder signing and verification for SchemaPin
// v1.3 / v1.4.
//
// Extends SchemaPin's ECDSA P-256 signing to cover file-based skill folders
// (AgentSkills spec). Same keys, same .well-known discovery, new canonicalization
// target.
//
// # Wire formats
//
// schemapin_version "1.4" (the default for every new signature):
//
//   - The directory is canonicalized with CanonicalizeSkill (skill
//     canonicalization v2, spec section 4b): every entry is hashed as
//     SHA-256("f" || be64(len(path)) || path || be64(len(content)) || content)
//     and the root hash is SHA-256 over be64(len(path)) || path || digest for
//     every entry in code-point path order. Symlinks are rejected.
//   - skill_hash is "sha256:" + hex(root_hash).
//   - The signature covers the entire signature document: the document is
//     built with signature "", canonicalized with schemapin-v1 and signed as
//     ECDSA-P256(SHA-256(canonical_bytes)). expires_at, schema_version,
//     previous_hash, canonicalization, domain, skill_name, signer_kid,
//     signed_at and file_manifest are therefore all integrity-protected.
//
// schemapin_version "1.3" (legacy, verify-only):
//
//   - Entries hashed as SHA-256(path || content), root hash SHA-256 of the
//     concatenated hex digests, symlinks silently skipped, and the signature
//     covers only the 32-byte root hash. None of the metadata fields are
//     signed; verifiers surface a legacy_signature_format warning.
//
// Verification is fail-closed on expiration and on domain mismatch.
package skill

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ThirdKeyAi/schemapin/go/pkg/core"
	"github.com/ThirdKeyAi/schemapin/go/pkg/crypto"
	"github.com/ThirdKeyAi/schemapin/go/pkg/discovery"
	"github.com/ThirdKeyAi/schemapin/go/pkg/domain"
	"github.com/ThirdKeyAi/schemapin/go/pkg/resolver"
	"github.com/ThirdKeyAi/schemapin/go/pkg/revocation"
	"github.com/ThirdKeyAi/schemapin/go/pkg/verification"
)

// SignatureFilename is the name of the signature file written into skill directories.
const SignatureFilename = ".schemapin.sig"

// Version constants written into the SchemapinVersion field.
const (
	// SchemapinVersion is written on every new signature (signed-document format).
	SchemapinVersion = "1.4"
	// SchemapinVersionLegacy is the root-hash-only format; accepted on
	// verification, never written.
	SchemapinVersionLegacy = "1.3"

	schemapinVersionV13 = SchemapinVersionLegacy
	schemapinVersionV14 = SchemapinVersion
)

// Caps enforced by CanonicalizeSkill.
const (
	MaxSkillFiles      = 10000
	MaxSkillTotalBytes = 256 * 1024 * 1024
)

// ErrSkillCanonicalization wraps every canonicalization failure.
var ErrSkillCanonicalization = errors.New("skill canonicalization error")

func canonErr(format string, args ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrSkillCanonicalization, fmt.Sprintf(format, args...))
}

// SkillSignature represents the JSON structure of a .schemapin.sig file.
//
// Optional v1.4 fields:
//   - ExpiresAt: verification fails with ErrSignatureExpired past this unless
//     the caller allows expired signatures.
//   - SchemaVersion: caller-supplied semver string identifying *this* version
//     of the signed artifact. Surfaced via VerificationResult for policy use.
//   - PreviousHash: sha256:<hex> of the prior signed version's SkillHash,
//     forming a hash chain. Pair with VerifyChain.
type SkillSignature struct {
	SchemapinVersion string `json:"schemapin_version"`
	SkillName        string `json:"skill_name"`
	SkillHash        string `json:"skill_hash"`
	Signature        string `json:"signature"`
	SignedAt         string `json:"signed_at"`
	ExpiresAt        string `json:"expires_at,omitempty"`
	SchemaVersion    string `json:"schema_version,omitempty"`
	PreviousHash     string `json:"previous_hash,omitempty"`
	// Canonicalization (v1.4) names the algorithm used to produce the
	// signing input. Absence is wire-equivalent to "schemapin-v1".
	// Verifiers MUST reject any other value as ErrCanonicalizationUnsupported.
	Canonicalization string            `json:"canonicalization,omitempty"`
	Domain           string            `json:"domain"`
	SignerKid        string            `json:"signer_kid"`
	FileManifest     map[string]string `json:"file_manifest"`
}

// SignOptions are optional sign-time parameters for SignSkillWithOptions.
type SignOptions struct {
	// SignerKid overrides the kid written into the signature. When empty,
	// the kid is derived from the public key fingerprint.
	SignerKid string
	// SkillName overrides the skill_name written into the signature. When
	// empty, it is parsed from SKILL.md frontmatter or falls back to the
	// directory basename.
	SkillName string
	// ExpiresIn sets a TTL relative to signing time. When non-zero, the
	// signature carries an RFC 3339 expires_at field (a negative value is
	// permitted and yields an already-expired signature, useful for tests).
	ExpiresIn time.Duration
	// SchemaVersion is a caller-supplied semver string identifying *this*
	// version of the signed artifact. Empty omits the field.
	SchemaVersion string
	// PreviousHash is sha256:<hex> of the prior signed version's SkillHash,
	// forming a hash chain. Pair with VerifyChain at verify time.
	PreviousHash string
	// Canonicalization is the algorithm identifier to write into the
	// signature. Empty omits the field on the wire (== implicit
	// "schemapin-v1"); pass "schemapin-v1" to declare it explicitly.
	Canonicalization string
}

// VerifyOptions tunes VerifySkillOfflineWithOptions.
type VerifyOptions struct {
	// Domain binds the skill to an expected domain: the signature's domain
	// field must equal it (ErrDomainMismatch otherwise). Pass it whenever you
	// know which domain the discovery document belongs to -- the signature's
	// own domain field is display-only. When empty the signature's domain is
	// used and a domain_unbound warning is surfaced.
	Domain string
	// ToolID is the pin-store key; defaults to the signature's skill_name.
	ToolID string
	// AllowExpired accepts expired signatures (degraded) instead of failing
	// with ErrSignatureExpired.
	AllowExpired bool
}

// TamperedFiles holds the result of comparing two file manifests.
type TamperedFiles struct {
	Modified []string
	Added    []string
	Removed  []string
}

type manifestEntry struct {
	path   string
	digest []byte
}

func be64(n int) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(n)) // #nosec G115 -- n is a non-negative length
	return b[:]
}

// walkV2 implements skill canonicalization v2.
func walkV2(dir, baseDir string, entries *[]manifestEntry, total *int64) error {
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return canonErr("failed to read directory %s: %v", dir, err)
	}
	for _, entry := range dirEntries {
		fullPath := filepath.Join(dir, entry.Name())
		info, err := os.Lstat(fullPath)
		if err != nil {
			return canonErr("failed to stat %s: %v", fullPath, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return canonErr("symlink not permitted in skill directory: %s", fullPath)
		}
		if info.IsDir() {
			if err := walkV2(fullPath, baseDir, entries, total); err != nil {
				return err
			}
			continue
		}
		if !info.Mode().IsRegular() {
			return canonErr("non-regular file in skill directory: %s", fullPath)
		}
		if dir == baseDir && entry.Name() == SignatureFilename {
			continue
		}
		relPath, err := filepath.Rel(baseDir, fullPath)
		if err != nil {
			return canonErr("failed to compute relative path: %v", err)
		}
		relStr := filepath.ToSlash(relPath)
		if !utf8.ValidString(relStr) {
			return canonErr("path is not valid UTF-8: %q", relStr)
		}
		data, err := os.ReadFile(fullPath) // #nosec G304 -- path constructed from the directory walk
		if err != nil {
			return canonErr("failed to read file %s: %v", fullPath, err)
		}
		*total += int64(len(data))
		if len(*entries)+1 > MaxSkillFiles {
			return canonErr("skill exceeds %d files", MaxSkillFiles)
		}
		if *total > MaxSkillTotalBytes {
			return canonErr("skill exceeds %d bytes", MaxSkillTotalBytes)
		}
		h := sha256.New()
		h.Write([]byte{'f'})
		h.Write(be64(len(relStr)))
		h.Write([]byte(relStr))
		h.Write(be64(len(data)))
		h.Write(data)
		*entries = append(*entries, manifestEntry{path: relStr, digest: h.Sum(nil)})
	}
	return nil
}

// CanonicalizeSkill walks a skill directory deterministically and computes the
// v2 root hash.
//
// Algorithm (spec section 4b):
//  1. Walk the tree; directories are not entries. The top-level .schemapin.sig
//     is excluded.
//  2. Any symlink (file or directory) or non-regular file aborts
//     canonicalization -- unsigned content must not be reachable from a
//     signed skill.
//  3. Paths are relative, forward-slash separated, UTF-8, sorted by code point.
//  4. Per entry: SHA-256(0x66 || be64(len(path)) || path || be64(len(content)) || content).
//  5. Root: SHA-256 over be64(len(path)) || path || entry_digest for every
//     entry in sorted order.
//
// Returns (root_hash_bytes, manifest, error).
func CanonicalizeSkill(skillDir string) ([]byte, map[string]string, error) {
	absDir, err := filepath.Abs(skillDir)
	if err != nil {
		return nil, nil, canonErr("failed to resolve skill directory: %v", err)
	}
	absDir, err = filepath.EvalSymlinks(absDir)
	if err != nil {
		return nil, nil, canonErr("failed to resolve skill directory: %v", err)
	}
	info, err := os.Stat(absDir)
	if err != nil || !info.IsDir() {
		return nil, nil, canonErr("not a directory: %s", skillDir)
	}

	var entries []manifestEntry
	var total int64
	if err := walkV2(absDir, absDir, &entries, &total); err != nil {
		return nil, nil, err
	}
	if len(entries) == 0 {
		return nil, nil, canonErr("skill directory is empty or contains no signable files: %s", skillDir)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })

	root := sha256.New()
	manifest := make(map[string]string, len(entries))
	for _, e := range entries {
		root.Write(be64(len(e.path)))
		root.Write([]byte(e.path))
		root.Write(e.digest)
		manifest[e.path] = "sha256:" + hex.EncodeToString(e.digest)
	}
	return root.Sum(nil), manifest, nil
}

// walkV1 is the legacy (schemapin_version "1.3") walk.
func walkV1(dir, baseDir string, manifest map[string]string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return canonErr("failed to read directory %s: %v", dir, err)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})
	for _, entry := range entries {
		fullPath := filepath.Join(dir, entry.Name())
		info, err := os.Lstat(fullPath)
		if err != nil {
			return canonErr("failed to stat %s: %v", fullPath, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if info.IsDir() {
			if err := walkV1(fullPath, baseDir, manifest); err != nil {
				return err
			}
			continue
		}
		if entry.Name() == SignatureFilename {
			continue
		}
		relPath, err := filepath.Rel(baseDir, fullPath)
		if err != nil {
			return canonErr("failed to compute relative path: %v", err)
		}
		relStr := filepath.ToSlash(relPath)
		fileBytes, err := os.ReadFile(fullPath) // #nosec G304 -- path constructed from the directory walk
		if err != nil {
			return canonErr("failed to read file %s: %v", fullPath, err)
		}
		h := sha256.New()
		h.Write([]byte(relStr))
		h.Write(fileBytes)
		manifest[relStr] = "sha256:" + hex.EncodeToString(h.Sum(nil))
	}
	return nil
}

// CanonicalizeSkillV1 is the legacy (schemapin_version "1.3") skill
// canonicalization. Kept only so that pre-1.4 signatures still verify. Per-file
// digest is SHA-256(path || content), the root hash is SHA-256 of the
// concatenated hex digests, symlinks are skipped and .schemapin.sig is
// excluded at any depth. Do not use for new signatures.
func CanonicalizeSkillV1(skillDir string) ([]byte, map[string]string, error) {
	absDir, err := filepath.Abs(skillDir)
	if err != nil {
		return nil, nil, canonErr("failed to resolve skill directory: %v", err)
	}
	absDir, err = filepath.EvalSymlinks(absDir)
	if err != nil {
		return nil, nil, canonErr("failed to resolve skill directory: %v", err)
	}
	manifest := make(map[string]string)
	if err := walkV1(absDir, absDir, manifest); err != nil {
		return nil, nil, err
	}
	if len(manifest) == 0 {
		return nil, nil, canonErr("skill directory is empty or contains no signable files: %s", skillDir)
	}
	keys := make([]string, 0, len(manifest))
	for k := range manifest {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var builder strings.Builder
	for _, k := range keys {
		builder.WriteString(strings.TrimPrefix(manifest[k], "sha256:"))
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
	fmRe := regexp.MustCompile(`(?s)^---\s*\n(.*?)\n---`)
	fmMatch := fmRe.FindStringSubmatch(text)
	if fmMatch == nil {
		return filepath.Base(absDir)
	}
	frontmatter := fmMatch[1]
	nameRe := regexp.MustCompile(`(?m)^name:\s*['"]?([^'"#\n]+?)['"]?\s*$`)
	nameMatch := nameRe.FindStringSubmatch(frontmatter)
	if nameMatch == nil {
		return filepath.Base(absDir)
	}
	return strings.TrimSpace(nameMatch[1])
}

// LoadSignature reads and parses the .schemapin.sig file from a skill directory.
//
// An explicitly empty "canonicalization" field is rejected: the empty string
// is not a supported algorithm identifier, and the Go struct cannot otherwise
// distinguish it from an absent field.
func LoadSignature(skillDir string) (*SkillSignature, error) {
	sigPath := filepath.Join(skillDir, SignatureFilename)
	data, err := os.ReadFile(sigPath) // #nosec G304 -- path constructed from user-provided skill directory
	if err != nil {
		return nil, fmt.Errorf("failed to read signature file: %w", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse signature file: %w", err)
	}
	if v, ok := raw["canonicalization"]; ok && string(v) == `""` {
		return nil, fmt.Errorf("failed to parse signature file: canonicalization must not be empty")
	}

	var sig SkillSignature
	if err := json.Unmarshal(data, &sig); err != nil {
		return nil, fmt.Errorf("failed to parse signature file: %w", err)
	}
	return &sig, nil
}

// SigningInput builds the canonical bytes a v1.4 signature covers: the known
// signature fields (unknown fields are ignored and therefore unprotected) with
// absent / empty optional fields dropped, signature forced to "" and the
// whole document canonicalized with schemapin-v1.
func SigningInput(sig *SkillSignature) ([]byte, error) {
	if sig == nil {
		return nil, fmt.Errorf("signature document is nil")
	}
	required := map[string]string{
		"schemapin_version": sig.SchemapinVersion,
		"skill_name":        sig.SkillName,
		"skill_hash":        sig.SkillHash,
		"signed_at":         sig.SignedAt,
		"domain":            sig.Domain,
		"signer_kid":        sig.SignerKid,
	}
	doc := make(map[string]interface{}, 12)
	for k, v := range required {
		if v == "" {
			return nil, fmt.Errorf("signature document field %q is missing", k)
		}
		doc[k] = v
	}
	if sig.FileManifest == nil {
		return nil, fmt.Errorf("file_manifest must be an object")
	}
	manifest := make(map[string]interface{}, len(sig.FileManifest))
	for k, v := range sig.FileManifest {
		manifest[k] = v
	}
	doc["file_manifest"] = manifest
	for k, v := range map[string]string{
		"expires_at":       sig.ExpiresAt,
		"schema_version":   sig.SchemaVersion,
		"previous_hash":    sig.PreviousHash,
		"canonicalization": sig.Canonicalization,
	} {
		if v != "" {
			doc[k] = v
		}
	}
	doc["signature"] = ""
	canonical, err := core.CanonicalizeValue(doc)
	if err != nil {
		return nil, err
	}
	return []byte(canonical), nil
}

// SignSkill canonicalizes a skill directory, signs it, and writes .schemapin.sig.
//
// If signerKid is empty, it is auto-computed from the public key.
// If skillName is empty, it is parsed from SKILL.md (or falls back to dir name).
func SignSkill(skillDir, privateKeyPEM, domainName string, signerKid, skillName string) (*SkillSignature, error) {
	return SignSkillWithOptions(skillDir, privateKeyPEM, domainName, SignOptions{
		SignerKid: signerKid,
		SkillName: skillName,
	})
}

// SignSkillWithOptions canonicalizes a skill directory, signs it, and writes a
// v1.4 signature document. The whole document (including expires_at when
// options.ExpiresIn is non-zero, written as RFC 3339 "Z" with second
// precision) is covered by the signature.
func SignSkillWithOptions(skillDir, privateKeyPEM, domainName string, options SignOptions) (*SkillSignature, error) {
	normalized, err := domain.ValidateDomain(domainName)
	if err != nil {
		return nil, err
	}
	domainName = normalized

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

	now := time.Now().UTC().Truncate(time.Second)
	expiresAt := ""
	if options.ExpiresIn != 0 {
		expiresAt = now.Add(options.ExpiresIn).UTC().Format(time.RFC3339)
	}

	sig := &SkillSignature{
		SchemapinVersion: SchemapinVersion,
		SkillName:        skillName,
		SkillHash:        "sha256:" + hex.EncodeToString(rootHash),
		SignedAt:         now.Format(time.RFC3339),
		ExpiresAt:        expiresAt,
		SchemaVersion:    options.SchemaVersion,
		PreviousHash:     options.PreviousHash,
		Canonicalization: options.Canonicalization,
		Domain:           domainName,
		SignerKid:        signerKid,
		FileManifest:     manifest,
	}

	input, err := SigningInput(sig)
	if err != nil {
		return nil, err
	}
	sig.Signature, err = crypto.NewSignatureManager().SignHash(input, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
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

func versionTuple(version string) (int, int, bool) {
	parts := strings.Split(version, ".")
	if len(parts) != 2 {
		return 0, 0, false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || major < 0 || minor < 0 {
		return 0, 0, false
	}
	return major, minor, true
}

func isLegacyVersion(version string) bool {
	major, minor, ok := versionTuple(version)
	return ok && (major < 1 || (major == 1 && minor < 4))
}

func failure(domainName string, code verification.ErrorCode, msg string) *verification.VerificationResult {
	return &verification.VerificationResult{
		Valid:        false,
		Domain:       domainName,
		ErrorCode:    code,
		ErrorMessage: msg,
	}
}

// VerifySkillOffline verifies a signed skill folder offline using pre-fetched
// discovery and revocation data. The signature's own domain field is used for
// pinning and reporting with a domain_unbound warning; prefer
// VerifySkillOfflineWithOptions and bind the expected domain.
func VerifySkillOffline(
	skillDir string,
	disc *discovery.WellKnownResponse,
	sig *SkillSignature,
	rev *revocation.RevocationDocument,
	pinStore *verification.KeyPinStore,
	toolID string,
) *verification.VerificationResult {
	return VerifySkillOfflineWithOptions(skillDir, disc, sig, rev, pinStore, VerifyOptions{ToolID: toolID})
}

// VerifySkillOfflineWithOptions verifies a signed skill folder offline.
//
// Steps:
//  1. Load or accept signature data; check canonicalization
//  2. Bind the domain (opts.Domain must equal the signature's domain)
//  3. Validate discovery document, load key, compute fingerprint
//  4. Check revocation
//  5. TOFU pin check (read-only)
//  6. Recompute the root hash, require skill_hash to match, verify the
//     signature (over the whole document for 1.4, over the root hash for
//     legacy 1.3)
//  7. Expiration check (fail-closed unless opts.AllowExpired)
//  8. Pin on first use, return the result with lineage metadata
func VerifySkillOfflineWithOptions(
	skillDir string,
	disc *discovery.WellKnownResponse,
	sig *SkillSignature,
	rev *revocation.RevocationDocument,
	pinStore *verification.KeyPinStore,
	opts VerifyOptions,
) *verification.VerificationResult {
	// Step 1: Load signature if nil
	if sig == nil {
		var err error
		sig, err = LoadSignature(skillDir)
		if err != nil {
			return failure("", verification.ErrSignatureInvalid, "No usable .schemapin.sig found in skill directory: "+err.Error())
		}
	}

	toolID := opts.ToolID
	if toolID == "" {
		toolID = sig.SkillName
		if toolID == "" {
			toolID = filepath.Base(skillDir)
		}
	}

	if bad := verification.CheckCanonicalization(sig.Canonicalization); bad != "" {
		return failure(opts.Domain, verification.ErrCanonicalizationUnsupported,
			fmt.Sprintf("Unsupported canonicalization algorithm: %s", bad))
	}

	// Step 2: Domain binding
	var warnings []string
	var domainName string
	if opts.Domain != "" {
		normalized, err := domain.ValidateDomain(opts.Domain)
		if err != nil {
			return failure(opts.Domain, verification.ErrDomainInvalid, err.Error())
		}
		domainName = normalized
		if strings.ToLower(sig.Domain) != domainName {
			return failure(domainName, verification.ErrDomainMismatch,
				fmt.Sprintf("signature domain %q does not match expected domain %q", sig.Domain, domainName))
		}
	} else {
		normalized, err := domain.ValidateDomain(sig.Domain)
		if err != nil {
			return failure("", verification.ErrDomainInvalid, "signature domain is invalid: "+err.Error())
		}
		domainName = normalized
		warnings = append(warnings, verification.WarningDomainUnbound)
	}

	// Step 3: Validate discovery document
	if disc == nil || disc.PublicKeyPEM == "" || !strings.Contains(disc.PublicKeyPEM, "-----BEGIN PUBLIC KEY-----") {
		return failure(domainName, verification.ErrDiscoveryInvalid, "Discovery document missing or invalid public_key_pem")
	}
	keyManager := crypto.NewKeyManager()
	publicKey, err := keyManager.LoadPublicKeyPEM(disc.PublicKeyPEM)
	if err != nil {
		return failure(domainName, verification.ErrKeyNotFound, fmt.Sprintf("Failed to load public key: %v", err))
	}
	fingerprint, err := keyManager.CalculateKeyFingerprintFromPEM(disc.PublicKeyPEM)
	if err != nil {
		return failure(domainName, verification.ErrKeyNotFound, fmt.Sprintf("Failed to calculate fingerprint: %v", err))
	}

	// Step 4: Check revocation
	if err := revocation.CheckRevocationCombined(disc.RevokedKeys, rev, fingerprint); err != nil {
		return failure(domainName, verification.ErrKeyRevoked, err.Error())
	}

	// Step 5: TOFU pin check (read-only until the signature verifies)
	var pinResult verification.PinResult
	if pinStore != nil {
		pinResult = pinStore.Check(toolID, domainName, fingerprint)
		if pinResult == verification.PinChanged {
			return failure(domainName, verification.ErrKeyPinMismatch, "Key fingerprint changed since last use")
		}
	}

	// Step 6: Canonicalize and verify
	if _, _, ok := versionTuple(sig.SchemapinVersion); !ok {
		return failure(domainName, verification.ErrSignatureInvalid,
			fmt.Sprintf("unsupported schemapin_version %q", sig.SchemapinVersion))
	}
	legacy := isLegacyVersion(sig.SchemapinVersion)
	var rootHash []byte
	if legacy {
		rootHash, _, err = CanonicalizeSkillV1(skillDir)
	} else {
		rootHash, _, err = CanonicalizeSkill(skillDir)
	}
	if err != nil {
		return failure(domainName, verification.ErrSchemaCanonicalizationFailed, fmt.Sprintf("Failed to canonicalize skill: %v", err))
	}

	sigManager := crypto.NewSignatureManager()
	var valid bool
	if legacy {
		valid = sigManager.VerifySignature(rootHash, sig.Signature, publicKey)
		warnings = append(warnings, verification.WarningLegacySignatureFormat)
	} else {
		if sig.SkillHash != "sha256:"+hex.EncodeToString(rootHash) {
			return failure(domainName, verification.ErrSignatureInvalid, "skill_hash does not match the directory contents")
		}
		input, err := SigningInput(sig)
		if err != nil {
			return failure(domainName, verification.ErrSignatureInvalid, "malformed signature document: "+err.Error())
		}
		valid = sigManager.VerifySignature(input, sig.Signature, publicKey)
	}
	if !valid {
		return failure(domainName, verification.ErrSignatureInvalid, "Signature verification failed")
	}

	// Step 7: Expiration (fail-closed by default)
	if warnings == nil {
		warnings = []string{}
	}
	result := &verification.VerificationResult{
		Valid:         true,
		Domain:        domainName,
		DeveloperName: disc.DeveloperName,
		Warnings:      warnings,
	}
	result = result.WithExpirationPolicy(sig.ExpiresAt, opts.AllowExpired)
	if !result.Valid {
		return result
	}

	// Step 8: Pin only now, then surface lineage metadata
	if pinStore != nil {
		if pinResult == verification.PinFirstUse {
			pinStore.Pin(toolID, domainName, fingerprint)
		}
		result.KeyPinning = &verification.KeyPinningStatus{Status: string(pinResult)}
	}
	return result.WithLineageMetadata(sig.SchemaVersion, sig.PreviousHash)
}

// VerifySkillWithResolver verifies a signed skill folder using a resolver for
// discovery and revocation. The signature's domain must equal domainName
// (checked before any network I/O) and revocation is fail-closed.
func VerifySkillWithResolver(
	skillDir, domainName string,
	r resolver.SchemaResolver,
	pinStore *verification.KeyPinStore,
	toolID string,
) *verification.VerificationResult {
	return VerifySkillWithResolverOptions(skillDir, domainName, r, pinStore, toolID, verification.ResolverOptions{})
}

// VerifySkillWithResolverOptions is VerifySkillWithResolver with explicit
// policy knobs.
func VerifySkillWithResolverOptions(
	skillDir, domainName string,
	r resolver.SchemaResolver,
	pinStore *verification.KeyPinStore,
	toolID string,
	ropts verification.ResolverOptions,
) *verification.VerificationResult {
	normalized, err := domain.ValidateDomain(domainName)
	if err != nil {
		return failure(domainName, verification.ErrDomainInvalid, err.Error())
	}
	domainName = normalized

	sig, err := LoadSignature(skillDir)
	if err != nil {
		return failure(domainName, verification.ErrSignatureInvalid, "No usable .schemapin.sig found in skill directory: "+err.Error())
	}
	if strings.ToLower(sig.Domain) != domainName {
		return failure(domainName, verification.ErrDomainMismatch,
			fmt.Sprintf("signature domain %q does not match expected domain %q", sig.Domain, domainName))
	}

	disc, err := r.ResolveDiscovery(domainName)
	if err != nil {
		return failure(domainName, verification.ErrDiscoveryFetchFailed, fmt.Sprintf("Could not resolve discovery for domain: %s", domainName))
	}

	rev, err := r.ResolveRevocation(domainName, disc)
	if err != nil {
		if !ropts.AllowUnreachableRevocation {
			return failure(domainName, verification.ErrDiscoveryFetchFailed, fmt.Sprintf("Revocation document unreachable (fail-closed): %v", err))
		}
		rev = nil
	}

	return VerifySkillOfflineWithOptions(skillDir, disc, sig, rev, pinStore, VerifyOptions{
		Domain:       domainName,
		ToolID:       toolID,
		AllowExpired: ropts.AllowExpired,
	})
}

// DetectTamperedFiles compares a current file manifest against a signed manifest.
// Only meaningful for schemapin_version >= "1.4" documents, whose file_manifest
// is covered by the signature; for legacy 1.3 documents the manifest is
// unsigned and this is a diagnostic aid only.
func DetectTamperedFiles(current, signed map[string]string) *TamperedFiles {
	result := &TamperedFiles{
		Modified: []string{},
		Added:    []string{},
		Removed:  []string{},
	}
	for k, v := range current {
		if sv, ok := signed[k]; !ok {
			result.Added = append(result.Added, k)
		} else if v != sv {
			result.Modified = append(result.Modified, k)
		}
	}
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
	// ChainErrorLegacy indicates one of the documents is a legacy 1.3
	// signature whose skill_hash is not covered by its signature.
	ChainErrorLegacy
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
	case ChainErrorLegacy:
		return "legacy 1.3 signature documents carry an unsigned skill_hash and cannot anchor a chain"
	default:
		return "unknown chain error"
	}
}

// VerifyChain verifies that current is the legitimate successor of previous
// via the previous_hash lineage chain.
//
// Checks current.PreviousHash == previous.SkillHash. This is a pure-metadata
// check -- no cryptography is re-evaluated. Both signatures must already be
// cryptographically verified separately via VerifySkillOffline, and both must
// be schemapin_version >= "1.4" documents so that skill_hash / previous_hash
// are covered by their signatures (legacy 1.3 documents are rejected).
func VerifyChain(current, previous *SkillSignature) error {
	if isLegacyVersion(current.SchemapinVersion) || isLegacyVersion(previous.SchemapinVersion) {
		return &ChainError{Kind: ChainErrorLegacy}
	}
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
