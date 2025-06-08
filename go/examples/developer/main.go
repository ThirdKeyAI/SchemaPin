// Package main demonstrates SchemaPin usage for tool developers.
package main

import (
	"fmt"
	"log"

	"github.com/jascha/schemapin-go/internal/version"
	"github.com/jascha/schemapin-go/pkg/crypto"
	"github.com/jascha/schemapin-go/pkg/utils"
)

func main() {
	fmt.Printf("SchemaPin Go Developer Example v%s\n", version.GetVersion())

	// Example: Generate a key pair
	keyManager := crypto.NewKeyManager()
	privateKey, err := keyManager.GenerateKeypair()
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}

	// Export keys to PEM format
	privateKeyPEM, err := keyManager.ExportPrivateKeyPEM(privateKey)
	if err != nil {
		log.Fatalf("Failed to export private key: %v", err)
	}

	publicKeyPEM, err := keyManager.ExportPublicKeyPEM(&privateKey.PublicKey)
	if err != nil {
		log.Fatalf("Failed to export public key: %v", err)
	}

	fmt.Println("Generated ECDSA key pair:")
	fmt.Printf("Private Key (first 50 chars): %s...\n", privateKeyPEM[:50])
	fmt.Printf("Public Key (first 50 chars): %s...\n", publicKeyPEM[:50])

	// Example: Create .well-known response
	wellKnown := utils.CreateWellKnownResponse(
		publicKeyPEM,
		"Example Developer",
		"security@example.com",
		[]string{}, // No revoked keys
		"1.1",
	)

	fmt.Printf("\n.well-known response created with %d fields\n", len(wellKnown))

	// Example: Sign a schema (placeholder)
	schema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"name": map[string]interface{}{
				"type": "string",
			},
		},
	}

	signingWorkflow, err := utils.NewSchemaSigningWorkflow(privateKeyPEM)
	if err != nil {
		log.Fatalf("Failed to create signing workflow: %v", err)
	}

	// This will return "not implemented" for now
	signature, err := signingWorkflow.SignSchema(schema)
	if err != nil {
		fmt.Printf("Schema signing (not yet implemented): %v\n", err)
	} else {
		fmt.Printf("Schema signature: %s\n", signature)
	}

	fmt.Println("\nDeveloper example completed!")
}
