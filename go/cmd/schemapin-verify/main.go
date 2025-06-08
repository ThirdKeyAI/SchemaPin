// Package main provides the schemapin-verify CLI tool for verifying signed schemas.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/ThirdKeyAi/schemapin/go/internal/version"
	"github.com/ThirdKeyAi/schemapin/go/pkg/core"
	"github.com/ThirdKeyAi/schemapin/go/pkg/crypto"
	"github.com/ThirdKeyAi/schemapin/go/pkg/discovery"
	"github.com/ThirdKeyAi/schemapin/go/pkg/interactive"
	"github.com/ThirdKeyAi/schemapin/go/pkg/pinning"
)

var (
	schemaFile      string
	batchDir        string
	stdinInput      bool
	publicKeyFile   string
	domain          string
	toolID          string
	pinningDB       string
	interactiveMode bool
	autoPin         bool
	pattern         string
	verbose         bool
	quiet           bool
	jsonOutput      bool
	exitCode        bool
)

type SignedSchema struct {
	Schema    map[string]interface{} `json:"schema"`
	Signature string                 `json:"signature"`
	SignedAt  string                 `json:"signed_at,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

type VerificationResult struct {
	Valid              bool                   `json:"valid"`
	VerificationMethod string                 `json:"verification_method"`
	KeyFingerprint     string                 `json:"key_fingerprint,omitempty"`
	KeySource          string                 `json:"key_source,omitempty"`
	File               string                 `json:"file,omitempty"`
	Error              string                 `json:"error,omitempty"`
	Pinned             bool                   `json:"pinned,omitempty"`
	FirstUse           bool                   `json:"first_use,omitempty"`
	DeveloperInfo      map[string]string      `json:"developer_info,omitempty"`
	SignedAt           string                 `json:"signed_at,omitempty"`
	Metadata           map[string]interface{} `json:"metadata,omitempty"`
}

func main() {
	var rootCmd = &cobra.Command{
		Use:   "schemapin-verify",
		Short: "Verify signed JSON schemas with SchemaPin",
		Long: `Verify signed JSON schemas using public key discovery or direct public key verification.

This tool verifies cryptographic signatures on schemas and supports interactive
key pinning for Trust-On-First-Use (TOFU) security.`,
		Example: `  schemapin-verify --schema signed_schema.json --public-key public.pem
  schemapin-verify --schema signed_schema.json --domain example.com --tool-id my-tool
  schemapin-verify --batch schemas/ --domain example.com --auto-pin
  echo '{"schema": {...}, "signature": "..."}' | schemapin-verify --stdin --domain example.com`,
		RunE: runVerify,
	}

	// Input options
	rootCmd.Flags().StringVar(&schemaFile, "schema", "", "Signed schema file to verify")
	rootCmd.Flags().StringVar(&batchDir, "batch", "", "Directory containing signed schema files")
	rootCmd.Flags().BoolVar(&stdinInput, "stdin", false, "Read signed schema from stdin")
	rootCmd.MarkFlagsOneRequired("schema", "batch", "stdin")
	rootCmd.MarkFlagsMutuallyExclusive("schema", "batch", "stdin")

	// Verification method options
	rootCmd.Flags().StringVar(&publicKeyFile, "public-key", "", "Public key file for verification (PEM format)")
	rootCmd.Flags().StringVar(&domain, "domain", "", "Domain for public key discovery")
	rootCmd.MarkFlagsOneRequired("public-key", "domain")
	rootCmd.MarkFlagsMutuallyExclusive("public-key", "domain")

	// Discovery and pinning options
	rootCmd.Flags().StringVar(&toolID, "tool-id", "", "Tool identifier for key pinning")
	rootCmd.Flags().StringVar(&pinningDB, "pinning-db", "", "Path to key pinning database")
	rootCmd.Flags().BoolVar(&interactiveMode, "interactive", false, "Enable interactive key pinning prompts")
	rootCmd.Flags().BoolVar(&autoPin, "auto-pin", false, "Automatically pin keys on first use")

	// Batch processing options
	rootCmd.Flags().StringVar(&pattern, "pattern", "*.json", "File pattern for batch processing")

	// Output options
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output with security information")
	rootCmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Quiet output (only errors)")
	rootCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results as JSON")
	rootCmd.Flags().BoolVar(&exitCode, "exit-code", false, "Exit with non-zero code if any verification fails")
	rootCmd.MarkFlagsMutuallyExclusive("quiet", "verbose")

	rootCmd.Version = version.GetVersion()

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runVerify(cmd *cobra.Command, args []string) error {
	// Validate arguments
	if domain != "" && interactiveMode && toolID == "" {
		return fmt.Errorf("--tool-id is required for interactive mode")
	}

	var results []VerificationResult

	if stdinInput {
		// Process stdin
		result, err := processStdin()
		if err != nil {
			return err
		}
		results = append(results, result)

	} else if schemaFile != "" {
		// Process single schema
		result, err := processSingleSchema(schemaFile)
		if err != nil {
			return err
		}
		results = append(results, result)

	} else if batchDir != "" {
		// Process batch
		batchResults, err := processBatch(batchDir)
		if err != nil {
			return err
		}
		results = append(results, batchResults...)
	}

	// Output results
	if jsonOutput {
		output := map[string]interface{}{
			"results": results,
			"total":   len(results),
			"valid":   countValid(results),
			"invalid": countInvalid(results),
		}
		outputJSON, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal result: %w", err)
		}
		fmt.Println(string(outputJSON))
	} else {
		// Human-readable output
		if !quiet {
			for _, result := range results {
				displayVerificationResult(result, verbose)
			}

			if len(results) > 1 {
				validCount := countValid(results)
				fmt.Printf("\nSummary: %d/%d schemas verified successfully\n", validCount, len(results))
			}
		}
	}

	// Exit code handling
	if exitCode {
		invalidCount := countInvalid(results)
		if invalidCount > 0 {
			os.Exit(1)
		}
	}

	return nil
}

func processStdin() (VerificationResult, error) {
	stdinData, err := io.ReadAll(os.Stdin)
	if err != nil {
		return VerificationResult{}, fmt.Errorf("failed to read from stdin: %w", err)
	}

	var signedSchema SignedSchema
	if err := json.Unmarshal(stdinData, &signedSchema); err != nil {
		return VerificationResult{}, fmt.Errorf("failed to parse JSON from stdin: %w", err)
	}

	if signedSchema.Schema == nil || signedSchema.Signature == "" {
		return VerificationResult{}, fmt.Errorf("invalid signed schema format from stdin")
	}

	result, err := verifySignedSchema(&signedSchema)
	if err != nil {
		return VerificationResult{}, err
	}

	result.Metadata = signedSchema.Metadata
	result.SignedAt = signedSchema.SignedAt
	return result, nil
}

func processSingleSchema(schemaPath string) (VerificationResult, error) {
	signedSchema, err := loadSignedSchema(schemaPath)
	if err != nil {
		return VerificationResult{}, err
	}

	result, err := verifySignedSchema(signedSchema)
	if err != nil {
		return VerificationResult{}, err
	}

	result.File = schemaPath
	result.Metadata = signedSchema.Metadata
	result.SignedAt = signedSchema.SignedAt
	return result, nil
}

func processBatch(batchPath string) ([]VerificationResult, error) {
	files, err := filepath.Glob(filepath.Join(batchPath, pattern))
	if err != nil {
		return nil, fmt.Errorf("failed to glob files: %w", err)
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no schema files found matching pattern '%s' in %s", pattern, batchPath)
	}

	var results []VerificationResult
	for _, file := range files {
		result, err := processSingleSchema(file)
		if err != nil {
			results = append(results, VerificationResult{
				File:               file,
				Valid:              false,
				Error:              err.Error(),
				VerificationMethod: getVerificationMethod(),
			})
		} else {
			results = append(results, result)
		}
	}

	return results, nil
}

func loadSignedSchema(schemaPath string) (*SignedSchema, error) {
	data, err := os.ReadFile(schemaPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read schema file: %w", err)
	}

	var signedSchema SignedSchema
	if err := json.Unmarshal(data, &signedSchema); err != nil {
		return nil, fmt.Errorf("failed to parse JSON schema: %w", err)
	}

	if signedSchema.Schema == nil || signedSchema.Signature == "" {
		return nil, fmt.Errorf("invalid signed schema format - missing required fields")
	}

	return &signedSchema, nil
}

func verifySignedSchema(signedSchema *SignedSchema) (VerificationResult, error) {
	if publicKeyFile != "" {
		return verifyWithPublicKey(signedSchema.Schema, signedSchema.Signature)
	} else {
		return verifyWithDiscovery(signedSchema.Schema, signedSchema.Signature)
	}
}

func verifyWithPublicKey(schema map[string]interface{}, signature string) (VerificationResult, error) {
	// Load public key
	keyData, err := os.ReadFile(publicKeyFile)
	if err != nil {
		return VerificationResult{}, fmt.Errorf("failed to read public key file: %w", err)
	}

	keyManager := crypto.NewKeyManager()
	publicKey, err := keyManager.LoadPublicKeyPEM(string(keyData))
	if err != nil {
		return VerificationResult{}, fmt.Errorf("failed to load public key: %w", err)
	}

	// Canonicalize and hash schema
	core := core.NewSchemaPinCore()
	schemaHash, err := core.CanonicalizeAndHash(schema)
	if err != nil {
		return VerificationResult{}, fmt.Errorf("failed to canonicalize schema: %w", err)
	}

	// Verify signature
	sigManager := crypto.NewSignatureManager()
	isValid := sigManager.VerifySchemaSignature(schemaHash, signature, publicKey)

	fingerprint, err := keyManager.CalculateKeyFingerprint(publicKey)
	if err != nil {
		fingerprint = "unknown"
	}

	return VerificationResult{
		Valid:              isValid,
		VerificationMethod: "public_key",
		KeyFingerprint:     fingerprint,
		KeySource:          publicKeyFile,
	}, nil
}

func verifyWithDiscovery(schema map[string]interface{}, signature string) (VerificationResult, error) {
	// Initialize discovery
	discoveryClient := discovery.NewPublicKeyDiscovery()

	// Get public key from .well-known endpoint
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	publicKeyPEM, err := discoveryClient.GetPublicKeyPEM(ctx, domain)
	if err != nil {
		return VerificationResult{}, fmt.Errorf("failed to discover public key: %w", err)
	}

	// Load public key
	keyManager := crypto.NewKeyManager()
	publicKey, err := keyManager.LoadPublicKeyPEM(publicKeyPEM)
	if err != nil {
		return VerificationResult{}, fmt.Errorf("failed to load discovered public key: %w", err)
	}

	// Check if key is revoked
	isNotRevoked, err := discoveryClient.ValidateKeyNotRevoked(ctx, publicKeyPEM, domain)
	if err != nil {
		// If we can't check revocation, proceed with caution
		isNotRevoked = true
	}

	if !isNotRevoked {
		return VerificationResult{
			Valid:              false,
			VerificationMethod: "discovery",
			Error:              "public key has been revoked",
		}, nil
	}

	// Handle interactive pinning if enabled
	if interactiveMode && toolID != "" {
		pinningManager, err := createPinningManager()
		if err != nil {
			return VerificationResult{}, fmt.Errorf("failed to create pinning manager: %w", err)
		}
		defer pinningManager.Close()

		// Get developer info
		developerInfo, err := discoveryClient.GetDeveloperInfo(ctx, domain)
		if err != nil {
			developerInfo = map[string]string{
				"developer_name": "Unknown",
				"schema_version": "1.0",
			}
		}

		// Verify with interactive pinning
		pinned, err := pinningManager.VerifyWithInteractivePinning(toolID, domain, publicKeyPEM, developerInfo["developer_name"])
		if err != nil {
			return VerificationResult{}, fmt.Errorf("interactive pinning failed: %w", err)
		}

		if !pinned {
			return VerificationResult{
				Valid:              false,
				VerificationMethod: "discovery_interactive",
				Error:              "key not accepted by user",
			}, nil
		}
	}

	// Canonicalize and hash schema
	core := core.NewSchemaPinCore()
	schemaHash, err := core.CanonicalizeAndHash(schema)
	if err != nil {
		return VerificationResult{}, fmt.Errorf("failed to canonicalize schema: %w", err)
	}

	// Verify signature
	sigManager := crypto.NewSignatureManager()
	isValid := sigManager.VerifySchemaSignature(schemaHash, signature, publicKey)

	fingerprint, err := keyManager.CalculateKeyFingerprint(publicKey)
	if err != nil {
		fingerprint = "unknown"
	}

	// Get developer info for result
	developerInfo, err := discoveryClient.GetDeveloperInfo(ctx, domain)
	if err != nil {
		developerInfo = map[string]string{
			"developer_name": "Unknown",
			"schema_version": "1.0",
		}
	}

	result := VerificationResult{
		Valid:              isValid,
		VerificationMethod: "discovery",
		KeyFingerprint:     fingerprint,
		KeySource:          fmt.Sprintf("https://%s/.well-known/schemapin.json", domain),
		DeveloperInfo:      developerInfo,
	}

	if interactiveMode {
		result.VerificationMethod = "discovery_interactive"
	}

	return result, nil
}

func createPinningManager() (*pinning.KeyPinning, error) {
	var handler interactive.InteractiveHandler
	if interactiveMode {
		handler = interactive.NewConsoleInteractiveHandler()
	}

	mode := pinning.PinningModeInteractive
	if autoPin {
		mode = pinning.PinningModeAutomatic
	}

	return pinning.NewKeyPinning(pinningDB, mode, handler)
}

func getVerificationMethod() string {
	if publicKeyFile != "" {
		return "public_key"
	} else if interactiveMode {
		return "discovery_interactive"
	} else {
		return "discovery"
	}
}

func displayVerificationResult(result VerificationResult, verbose bool) {
	fileInfo := ""
	if result.File != "" {
		fileInfo = fmt.Sprintf(" (%s)", result.File)
	}

	if result.Valid {
		fmt.Printf("✅ VALID%s\n", fileInfo)
		if verbose {
			fmt.Printf("   Method: %s\n", result.VerificationMethod)
			if result.KeyFingerprint != "" {
				fmt.Printf("   Key fingerprint: %s\n", result.KeyFingerprint)
			}
			if result.KeySource != "" {
				fmt.Printf("   Key source: %s\n", result.KeySource)
			}
			if result.Pinned {
				fmt.Println("   Key status: Pinned")
			}
			if result.FirstUse {
				fmt.Println("   Key status: First use")
			}
			if result.DeveloperInfo != nil && result.DeveloperInfo["developer_name"] != "" {
				fmt.Printf("   Developer: %s\n", result.DeveloperInfo["developer_name"])
			}
			if result.SignedAt != "" {
				fmt.Printf("   Signed at: %s\n", result.SignedAt)
			}
		}
	} else {
		fmt.Printf("❌ INVALID%s\n", fileInfo)
		if result.Error != "" {
			fmt.Printf("   Error: %s\n", result.Error)
		}
		if verbose && result.VerificationMethod != "" {
			fmt.Printf("   Method: %s\n", result.VerificationMethod)
		}
	}
}

func countValid(results []VerificationResult) int {
	count := 0
	for _, result := range results {
		if result.Valid {
			count++
		}
	}
	return count
}

func countInvalid(results []VerificationResult) int {
	count := 0
	for _, result := range results {
		if !result.Valid {
			count++
		}
	}
	return count
}
