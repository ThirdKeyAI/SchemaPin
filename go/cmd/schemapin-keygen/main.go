// Package main provides the schemapin-keygen CLI tool for generating ECDSA key pairs.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/ThirdKeyAi/schemapin/go/internal/version"
	"github.com/ThirdKeyAi/schemapin/go/pkg/crypto"
	"github.com/ThirdKeyAi/schemapin/go/pkg/discovery"
)

var (
	keyType       string
	keySize       int
	format        string
	outputDir     string
	prefix        string
	developer     string
	contact       string
	schemaVersion string
	wellKnown     bool
	verbose       bool
	quiet         bool
	jsonOutput    bool
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "schemapin-keygen",
		Short: "Generate cryptographic key pairs for SchemaPin",
		Long: `Generate ECDSA or RSA key pairs for signing JSON schemas with SchemaPin.

This tool generates cryptographic key pairs and optionally creates .well-known
templates for public key discovery.`,
		Example: `  schemapin-keygen --type ecdsa --output-dir ./keys --developer "Alice Corp"
  schemapin-keygen --type rsa --key-size 4096 --format der --output-dir ./keys
  schemapin-keygen --type ecdsa --well-known --developer "Bob Inc" --contact "security@bob.com"`,
		RunE: runKeygen,
	}

	rootCmd.Flags().StringVar(&keyType, "type", "ecdsa", "Key type to generate (ecdsa, rsa)")
	rootCmd.Flags().IntVar(&keySize, "key-size", 2048, "RSA key size in bits (2048, 3072, 4096)")
	rootCmd.Flags().StringVar(&format, "format", "pem", "Output format (pem, der)")
	rootCmd.Flags().StringVar(&outputDir, "output-dir", ".", "Output directory for key files")
	rootCmd.Flags().StringVar(&prefix, "prefix", "schemapin", "Filename prefix for generated keys")
	rootCmd.Flags().StringVar(&developer, "developer", "", "Developer or organization name for .well-known template")
	rootCmd.Flags().StringVar(&contact, "contact", "", "Contact information for .well-known template")
	rootCmd.Flags().StringVar(&schemaVersion, "schema-version", "1.1", "Schema version for .well-known template")
	rootCmd.Flags().BoolVar(&wellKnown, "well-known", false, "Generate .well-known/schemapin.json template")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Quiet output (only errors)")
	rootCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results as JSON")

	rootCmd.Version = version.GetVersion()

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runKeygen(cmd *cobra.Command, args []string) error {
	// Validate arguments
	if wellKnown && developer == "" {
		return fmt.Errorf("--developer is required when generating .well-known template")
	}

	if quiet && verbose {
		return fmt.Errorf("--quiet and --verbose are mutually exclusive")
	}

	if keyType != "ecdsa" && keyType != "rsa" {
		return fmt.Errorf("invalid key type: %s (must be ecdsa or rsa)", keyType)
	}

	if format != "pem" && format != "der" {
		return fmt.Errorf("invalid format: %s (must be pem or der)", format)
	}

	if keyType == "rsa" && keySize != 2048 && keySize != 3072 && keySize != 4096 {
		return fmt.Errorf("invalid RSA key size: %d (must be 2048, 3072, or 4096)", keySize)
	}

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Generate key pair
	var privateKeyPEM, publicKeyPEM, fingerprint string

	if keyType == "ecdsa" {
		keyManager := crypto.NewKeyManager()
		privateKey, err := keyManager.GenerateKeypair()
		if err != nil {
			return fmt.Errorf("failed to generate ECDSA key pair: %w", err)
		}

		privateKeyPEM, err = keyManager.ExportPrivateKeyPEM(privateKey)
		if err != nil {
			return fmt.Errorf("failed to export private key: %w", err)
		}

		publicKeyPEM, err = keyManager.ExportPublicKeyPEM(&privateKey.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to export public key: %w", err)
		}

		fingerprint, err = keyManager.CalculateKeyFingerprint(&privateKey.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to calculate fingerprint: %w", err)
		}
	} else {
		// RSA not implemented in this version - would need additional crypto functions
		return fmt.Errorf("RSA key generation not yet implemented")
	}

	// Determine file extensions
	if format == "der" {
		return fmt.Errorf("DER format not yet implemented")
	}
	ext := ".pem"

	privateKeyFile := filepath.Join(outputDir, fmt.Sprintf("%s_private%s", prefix, ext))
	publicKeyFile := filepath.Join(outputDir, fmt.Sprintf("%s_public%s", prefix, ext))

	// Write key files
	if err := os.WriteFile(privateKeyFile, []byte(privateKeyPEM), 0600); err != nil {
		return fmt.Errorf("failed to write private key file: %w", err)
	}

	if err := os.WriteFile(publicKeyFile, []byte(publicKeyPEM), 0644); err != nil {
		return fmt.Errorf("failed to write public key file: %w", err)
	}

	// Generate .well-known template if requested
	var wellKnownFile string
	if wellKnown {
		wellKnownData := &discovery.WellKnownResponse{
			SchemaVersion: schemaVersion,
			DeveloperName: developer,
			PublicKeyPEM:  publicKeyPEM,
			Contact:       contact,
		}

		wellKnownJSON, err := json.MarshalIndent(wellKnownData, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal .well-known data: %w", err)
		}

		wellKnownFile = filepath.Join(outputDir, "schemapin.json")
		if err := os.WriteFile(wellKnownFile, wellKnownJSON, 0644); err != nil {
			return fmt.Errorf("failed to write .well-known file: %w", err)
		}
	}

	// Output results
	result := map[string]interface{}{
		"key_type":         keyType,
		"key_size":         256, // ECDSA P-256
		"format":           format,
		"fingerprint":      fingerprint,
		"private_key_file": privateKeyFile,
		"public_key_file":  publicKeyFile,
	}

	if wellKnownFile != "" {
		result["well_known_file"] = wellKnownFile
	}

	if jsonOutput {
		output, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal result: %w", err)
		}
		fmt.Println(string(output))
	} else if !quiet {
		fmt.Printf("Generated %s key pair:\n", keyType)
		fmt.Printf("  Key type: %s\n", keyType)
		if keyType == "ecdsa" {
			fmt.Printf("  Curve: P-256\n")
		}
		fmt.Printf("  Format: %s\n", format)
		fmt.Printf("  Fingerprint: %s\n", fingerprint)
		fmt.Printf("  Private key: %s\n", privateKeyFile)
		fmt.Printf("  Public key: %s\n", publicKeyFile)
		if wellKnownFile != "" {
			fmt.Printf("  .well-known template: %s\n", wellKnownFile)
		}
	}

	if verbose && !jsonOutput {
		fmt.Printf("\nPublic key fingerprint: %s\n", fingerprint)
		if format == "pem" {
			fmt.Printf("\nPublic key PEM:\n%s\n", publicKeyPEM)
		}
	}

	return nil
}
