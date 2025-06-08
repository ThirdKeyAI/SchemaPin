// Package main provides the schemapin-sign CLI tool for signing schemas.
package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ThirdKeyAi/schemapin/go/internal/version"
	"github.com/ThirdKeyAi/schemapin/go/pkg/core"
	"github.com/ThirdKeyAi/schemapin/go/pkg/crypto"
)

var (
	keyFile      string
	schemaFile   string
	batchDir     string
	stdinInput   bool
	outputFile   string
	outputDir    string
	developer    string
	versionFlag  string
	description  string
	metadataFile string
	noValidate   bool
	pattern      string
	suffix       string
	verbose      bool
	quiet        bool
	jsonOutput   bool
)

type SignedSchema struct {
	Schema    map[string]interface{} `json:"schema"`
	Signature string                 `json:"signature"`
	SignedAt  string                 `json:"signed_at"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

type ProcessResult struct {
	Input  string `json:"input"`
	Output string `json:"output"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

func main() {
	var rootCmd = &cobra.Command{
		Use:   "schemapin-sign",
		Short: "Sign JSON schema files with SchemaPin",
		Long: `Sign JSON schema files using ECDSA private keys for SchemaPin verification.

This tool signs individual schemas, processes batches of schema files, or reads
from stdin to create signed schemas with cryptographic signatures.`,
		Example: `  schemapin-sign --key private.pem --schema schema.json --output signed_schema.json
		schemapin-sign --key private.pem --schema schema.json --developer "Alice Corp" --schema-version "1.0"
		schemapin-sign --key private.pem --batch schemas/ --output-dir signed/
		echo '{"type": "object"}' | schemapin-sign --key private.pem --stdin`,
		RunE: runSign,
	}

	// Input options
	rootCmd.Flags().StringVar(&schemaFile, "schema", "", "Input schema file")
	rootCmd.Flags().StringVar(&batchDir, "batch", "", "Directory containing schema files to sign")
	rootCmd.Flags().BoolVar(&stdinInput, "stdin", false, "Read schema from stdin")
	rootCmd.MarkFlagsOneRequired("schema", "batch", "stdin")
	rootCmd.MarkFlagsMutuallyExclusive("schema", "batch", "stdin")

	// Key options
	rootCmd.Flags().StringVar(&keyFile, "key", "", "Private key file (PEM format)")
	rootCmd.MarkFlagRequired("key")

	// Output options
	rootCmd.Flags().StringVar(&outputFile, "output", "", "Output file (default: stdout for single schema)")
	rootCmd.Flags().StringVar(&outputDir, "output-dir", "", "Output directory for batch processing")
	rootCmd.MarkFlagsMutuallyExclusive("output", "output-dir")

	// Metadata options
	rootCmd.Flags().StringVar(&developer, "developer", "", "Developer or organization name")
	rootCmd.Flags().StringVar(&versionFlag, "schema-version", "", "Schema version")
	rootCmd.Flags().StringVar(&description, "description", "", "Schema description")
	rootCmd.Flags().StringVar(&metadataFile, "metadata", "", "JSON file containing additional metadata")

	// Processing options
	rootCmd.Flags().BoolVar(&noValidate, "no-validate", false, "Skip schema format validation")
	rootCmd.Flags().StringVar(&pattern, "pattern", "*.json", "File pattern for batch processing")
	rootCmd.Flags().StringVar(&suffix, "suffix", "_signed", "Suffix for output files in batch mode")

	// Output format options
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Quiet output (only errors)")
	rootCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results as JSON")
	rootCmd.MarkFlagsMutuallyExclusive("quiet", "verbose")

	rootCmd.Version = version.GetVersion()

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runSign(cmd *cobra.Command, args []string) error {
	// Validate arguments
	if batchDir != "" && outputDir == "" {
		return fmt.Errorf("--output-dir is required for batch processing")
	}

	// Load private key
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("failed to read private key file: %w", err)
	}

	keyManager := crypto.NewKeyManager()
	privateKey, err := keyManager.LoadPrivateKeyPEM(string(keyData))
	if err != nil {
		return fmt.Errorf("failed to load private key: %w", err)
	}

	// Load additional metadata
	var additionalMetadata map[string]interface{}
	if metadataFile != "" {
		metadataData, err := os.ReadFile(metadataFile)
		if err != nil {
			return fmt.Errorf("failed to read metadata file: %w", err)
		}
		if err := json.Unmarshal(metadataData, &additionalMetadata); err != nil {
			return fmt.Errorf("failed to parse metadata file: %w", err)
		}
	}

	// Build metadata
	metadata := make(map[string]interface{})
	if developer != "" {
		metadata["developer"] = developer
	}
	if versionFlag != "" {
		metadata["version"] = versionFlag
	}
	if description != "" {
		metadata["description"] = description
	}
	for k, v := range additionalMetadata {
		metadata[k] = v
	}

	var results []ProcessResult

	if stdinInput {
		// Process stdin
		result, err := processStdin(privateKey, metadata)
		if err != nil {
			return err
		}
		results = append(results, result)

	} else if schemaFile != "" {
		// Process single schema
		result, err := processSingleSchema(schemaFile, privateKey, outputFile, metadata)
		if err != nil {
			return err
		}
		results = append(results, result)

	} else if batchDir != "" {
		// Process batch
		batchResults, err := processBatch(batchDir, privateKey, outputDir, metadata)
		if err != nil {
			return err
		}
		results = append(results, batchResults...)
	}

	// Output results
	if jsonOutput {
		output := map[string]interface{}{
			"results":    results,
			"total":      len(results),
			"successful": countSuccessful(results),
			"failed":     countFailed(results),
		}
		outputJSON, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal result: %w", err)
		}
		fmt.Println(string(outputJSON))
	} else if !quiet {
		successful := countSuccessful(results)
		failed := countFailed(results)

		if len(results) > 1 {
			fmt.Printf("Processed %d schemas: %d successful, %d failed\n", len(results), successful, failed)
		} else if successful == 1 && !stdinInput && outputFile != "" {
			fmt.Printf("Successfully signed schema: %s\n", results[0].Output)
		}
	}

	return nil
}

func processStdin(privateKey *ecdsa.PrivateKey, metadata map[string]interface{}) (ProcessResult, error) {
	stdinData, err := io.ReadAll(os.Stdin)
	if err != nil {
		return ProcessResult{}, fmt.Errorf("failed to read from stdin: %w", err)
	}

	var schema map[string]interface{}
	if err := json.Unmarshal(stdinData, &schema); err != nil {
		return ProcessResult{}, fmt.Errorf("failed to parse JSON from stdin: %w", err)
	}

	if !noValidate && !validateSchemaFormat(schema) {
		return ProcessResult{}, fmt.Errorf("schema format validation failed for stdin input")
	}

	signedSchema, err := signSchema(schema, privateKey, metadata)
	if err != nil {
		return ProcessResult{}, err
	}

	outputDest := "stdout"
	if outputFile != "" {
		outputJSON, err := json.MarshalIndent(signedSchema, "", "  ")
		if err != nil {
			return ProcessResult{}, fmt.Errorf("failed to marshal signed schema: %w", err)
		}
		if err := os.WriteFile(outputFile, outputJSON, 0644); err != nil {
			return ProcessResult{}, fmt.Errorf("failed to write output file: %w", err)
		}
		outputDest = outputFile
	} else {
		outputJSON, err := json.MarshalIndent(signedSchema, "", "  ")
		if err != nil {
			return ProcessResult{}, fmt.Errorf("failed to marshal signed schema: %w", err)
		}
		fmt.Println(string(outputJSON))
	}

	return ProcessResult{
		Input:  "stdin",
		Output: outputDest,
		Status: "success",
	}, nil
}

func processSingleSchema(schemaPath string, privateKey *ecdsa.PrivateKey, outputPath string, metadata map[string]interface{}) (ProcessResult, error) {
	schema, err := loadSchema(schemaPath)
	if err != nil {
		return ProcessResult{}, err
	}

	if !noValidate && !validateSchemaFormat(schema) {
		return ProcessResult{}, fmt.Errorf("schema format validation failed for %s", schemaPath)
	}

	signedSchema, err := signSchema(schema, privateKey, metadata)
	if err != nil {
		return ProcessResult{}, err
	}

	outputDest := "stdout"
	if outputPath != "" {
		outputJSON, err := json.MarshalIndent(signedSchema, "", "  ")
		if err != nil {
			return ProcessResult{}, fmt.Errorf("failed to marshal signed schema: %w", err)
		}
		if err := os.WriteFile(outputPath, outputJSON, 0644); err != nil {
			return ProcessResult{}, fmt.Errorf("failed to write output file: %w", err)
		}
		outputDest = outputPath
	} else {
		outputJSON, err := json.MarshalIndent(signedSchema, "", "  ")
		if err != nil {
			return ProcessResult{}, fmt.Errorf("failed to marshal signed schema: %w", err)
		}
		fmt.Println(string(outputJSON))
	}

	return ProcessResult{
		Input:  schemaPath,
		Output: outputDest,
		Status: "success",
	}, nil
}

func processBatch(batchPath string, privateKey *ecdsa.PrivateKey, outputPath string, metadata map[string]interface{}) ([]ProcessResult, error) {
	if err := os.MkdirAll(outputPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	files, err := filepath.Glob(filepath.Join(batchPath, pattern))
	if err != nil {
		return nil, fmt.Errorf("failed to glob files: %w", err)
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no schema files found matching pattern '%s' in %s", pattern, batchPath)
	}

	var results []ProcessResult
	for _, file := range files {
		base := filepath.Base(file)
		ext := filepath.Ext(base)
		name := strings.TrimSuffix(base, ext)
		outputFile := filepath.Join(outputPath, fmt.Sprintf("%s%s%s", name, suffix, ext))

		result, err := processSingleSchema(file, privateKey, outputFile, metadata)
		if err != nil {
			results = append(results, ProcessResult{
				Input:  file,
				Output: "",
				Status: "error",
				Error:  err.Error(),
			})
			if !quiet && !jsonOutput {
				fmt.Fprintf(os.Stderr, "Error processing %s: %v\n", file, err)
			}
		} else {
			results = append(results, result)
			if verbose && !jsonOutput {
				fmt.Printf("Signed: %s -> %s\n", file, outputFile)
			}
		}
	}

	return results, nil
}

func loadSchema(schemaPath string) (map[string]interface{}, error) {
	data, err := os.ReadFile(schemaPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read schema file: %w", err)
	}

	var schema map[string]interface{}
	if err := json.Unmarshal(data, &schema); err != nil {
		return nil, fmt.Errorf("failed to parse JSON schema: %w", err)
	}

	return schema, nil
}

func validateSchemaFormat(schema map[string]interface{}) bool {
	// Basic validation - check for common schema fields
	_, hasType := schema["type"]
	_, hasSchema := schema["$schema"]
	return hasType || hasSchema
}

func signSchema(schema map[string]interface{}, privateKey *ecdsa.PrivateKey, metadata map[string]interface{}) (*SignedSchema, error) {
	// Canonicalize and hash schema
	core := core.NewSchemaPinCore()
	schemaHash, err := core.CanonicalizeAndHash(schema)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize schema: %w", err)
	}

	// Sign the hash
	sigManager := crypto.NewSignatureManager()
	signature, err := sigManager.SignSchemaHash(schemaHash, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign schema: %w", err)
	}

	// Create signed schema
	signedSchema := &SignedSchema{
		Schema:    schema,
		Signature: signature,
		SignedAt:  time.Now().UTC().Format(time.RFC3339),
	}

	if len(metadata) > 0 {
		signedSchema.Metadata = metadata
	}

	return signedSchema, nil
}

func countSuccessful(results []ProcessResult) int {
	count := 0
	for _, result := range results {
		if result.Status == "success" {
			count++
		}
	}
	return count
}

func countFailed(results []ProcessResult) int {
	count := 0
	for _, result := range results {
		if result.Status == "error" {
			count++
		}
	}
	return count
}
