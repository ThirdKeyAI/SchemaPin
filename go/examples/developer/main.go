// Package main demonstrates SchemaPin usage for tool developers.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/ThirdKeyAi/schemapin/go/internal/version"
	"github.com/ThirdKeyAi/schemapin/go/pkg/crypto"
	"github.com/ThirdKeyAi/schemapin/go/pkg/utils"
)

func main() {
	fmt.Printf("SchemaPin Tool Developer Example v%s\n", version.GetVersion())
	fmt.Println(strings.Repeat("=", 40))

	// Step 1: Generate key pair
	fmt.Println("\n1. Generating ECDSA P-256 key pair...")
	keyManager := crypto.NewKeyManager()
	privateKey, err := keyManager.GenerateKeypair()
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}

	privateKeyPEM, err := keyManager.ExportPrivateKeyPEM(privateKey)
	if err != nil {
		log.Fatalf("Failed to export private key: %v", err)
	}

	publicKeyPEM, err := keyManager.ExportPublicKeyPEM(&privateKey.PublicKey)
	if err != nil {
		log.Fatalf("Failed to export public key: %v", err)
	}

	fmt.Println("✓ Key pair generated")

	// Step 2: Create sample tool schema
	fmt.Println("\n2. Creating sample tool schema...")
	sampleSchema := map[string]interface{}{
		"name":        "calculate_sum",
		"description": "Calculates the sum of two numbers",
		"parameters": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"a": map[string]interface{}{
					"type":        "number",
					"description": "First number",
				},
				"b": map[string]interface{}{
					"type":        "number",
					"description": "Second number",
				},
			},
			"required": []string{"a", "b"},
		},
	}

	fmt.Println("✓ Sample schema created")
	schemaJSON, _ := json.MarshalIndent(sampleSchema, "", "  ")
	fmt.Printf("Schema: %s\n", string(schemaJSON))

	// Step 3: Sign the schema
	fmt.Println("\n3. Signing schema...")
	signingWorkflow, err := utils.NewSchemaSigningWorkflow(privateKeyPEM)
	if err != nil {
		log.Fatalf("Failed to create signing workflow: %v", err)
	}

	signature, err := signingWorkflow.SignSchema(sampleSchema)
	if err != nil {
		log.Fatalf("Failed to sign schema: %v", err)
	}

	fmt.Println("✓ Schema signed")
	fmt.Printf("Signature: %s\n", signature)

	// Step 4: Create .well-known response
	fmt.Println("\n4. Creating .well-known/schemapin.json response...")
	wellKnownResponse := utils.CreateWellKnownResponse(
		publicKeyPEM,
		"Example Tool Developer",
		"developer@example.com",
		[]string{}, // No revoked keys
		"1.1",
	)

	fmt.Println("✓ .well-known response created")
	wellKnownJSON, _ := json.MarshalIndent(wellKnownResponse, "", "  ")
	fmt.Printf(".well-known content: %s\n", string(wellKnownJSON))

	// Step 5: Save files for demonstration
	fmt.Println("\n5. Saving demonstration files...")

	// Save private key (in real use, keep this secure!)
	if err := os.WriteFile("demo_private_key.pem", []byte(privateKeyPEM), 0600); err != nil {
		log.Fatalf("Failed to save private key: %v", err)
	}

	// Save schema with signature
	schemaWithSignature := map[string]interface{}{
		"schema":    sampleSchema,
		"signature": signature,
	}
	schemaSignedJSON, _ := json.MarshalIndent(schemaWithSignature, "", "  ")
	if err := os.WriteFile("demo_schema_signed.json", schemaSignedJSON, 0644); err != nil {
		log.Fatalf("Failed to save signed schema: %v", err)
	}

	// Save .well-known response
	wellKnownJSON, _ = json.MarshalIndent(wellKnownResponse, "", "  ")
	if err := os.WriteFile("demo_well_known.json", wellKnownJSON, 0644); err != nil {
		log.Fatalf("Failed to save well-known response: %v", err)
	}

	fmt.Println("✓ Files saved:")
	fmt.Println("  - demo_private_key.pem (keep secure!)")
	fmt.Println("  - demo_schema_signed.json")
	fmt.Println("  - demo_well_known.json")

	fmt.Println("\n" + strings.Repeat("=", 40))
	fmt.Println("Tool developer workflow complete!")
	fmt.Println("\nNext steps:")
	fmt.Println("1. Host demo_well_known.json at https://yourdomain.com/.well-known/schemapin.json")
	fmt.Println("2. Distribute demo_schema_signed.json with your tool")
	fmt.Println("3. Keep demo_private_key.pem secure and use it to sign future schema updates")
}
