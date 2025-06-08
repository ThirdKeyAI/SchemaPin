// Package main demonstrates cross-language compatibility between Go, Python, and JavaScript SchemaPin implementations.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/ThirdKeyAi/schemapin/go/internal/version"
	"github.com/ThirdKeyAi/schemapin/go/pkg/crypto"
	"github.com/ThirdKeyAi/schemapin/go/pkg/utils"
)

func main() {
	fmt.Printf("SchemaPin Cross-Language Compatibility Demo v%s\n", version.GetVersion())
	fmt.Println(strings.Repeat("=", 60))

	// Demo 1: Verify Python-generated signatures
	demoPythonCompatibility()

	// Demo 2: Verify JavaScript-generated signatures
	demoJavaScriptCompatibility()

	// Demo 3: Generate signatures for other languages to verify
	demoGenerateForOtherLanguages()

	fmt.Println("\n🎉 Cross-language compatibility demo completed!")
}

func demoPythonCompatibility() {
	fmt.Println("\n=== Python Compatibility Demo ===")

	// Check if we have Python-generated demo files
	pythonSchemaFile := "../../../python/examples/demo_schema_signed.json"
	pythonWellKnownFile := "../../../python/examples/demo_well_known.json"

	if _, err := os.Stat(pythonSchemaFile); os.IsNotExist(err) {
		fmt.Println("⚠️  Python demo files not found. Run python/examples/tool_developer.py first.")
		return
	}

	// Load Python-generated signed schema
	fmt.Println("1. Loading Python-generated signed schema...")
	schemaData, err := loadJSONFile(pythonSchemaFile)
	if err != nil {
		log.Printf("Failed to load Python schema file: %v", err)
		return
	}

	schema, ok := schemaData["schema"].(map[string]interface{})
	if !ok {
		log.Printf("Invalid schema format in Python file")
		return
	}

	signature, ok := schemaData["signature"].(string)
	if !ok {
		log.Printf("Invalid signature format in Python file")
		return
	}

	fmt.Println("✓ Python-generated schema loaded")

	// Load Python well-known response
	wellKnownData, err := loadJSONFile(pythonWellKnownFile)
	if err != nil {
		log.Printf("Failed to load Python well-known file: %v", err)
		return
	}

	publicKeyPEM, ok := wellKnownData["public_key_pem"].(string)
	if !ok {
		log.Printf("Invalid public key in Python well-known file")
		return
	}

	// Verify the Python signature using Go implementation
	fmt.Println("\n2. Verifying Python signature with Go implementation...")

	schemaHash, err := utils.CalculateSchemaHash(schema)
	if err != nil {
		log.Printf("Failed to calculate schema hash: %v", err)
		return
	}

	valid, err := utils.VerifySignatureOnly(schemaHash, signature, publicKeyPEM)
	if err != nil {
		log.Printf("Failed to verify signature: %v", err)
		return
	}

	if valid {
		fmt.Println("✅ Python signature verified successfully with Go!")
		fmt.Println("🔗 Cross-language compatibility confirmed: Python → Go")
	} else {
		fmt.Println("❌ Python signature verification failed")
	}
}

func demoJavaScriptCompatibility() {
	fmt.Println("\n=== JavaScript Compatibility Demo ===")

	// Check if we have JavaScript-generated demo files
	jsSchemaFile := "../../../javascript/demo_schema_signed.json"
	jsWellKnownFile := "../../../javascript/demo_well_known.json"

	if _, err := os.Stat(jsSchemaFile); os.IsNotExist(err) {
		fmt.Println("⚠️  JavaScript demo files not found. Run javascript/examples/developer.js first.")
		return
	}

	// Load JavaScript-generated signed schema
	fmt.Println("1. Loading JavaScript-generated signed schema...")
	schemaData, err := loadJSONFile(jsSchemaFile)
	if err != nil {
		log.Printf("Failed to load JavaScript schema file: %v", err)
		return
	}

	schema, ok := schemaData["schema"].(map[string]interface{})
	if !ok {
		log.Printf("Invalid schema format in JavaScript file")
		return
	}

	signature, ok := schemaData["signature"].(string)
	if !ok {
		log.Printf("Invalid signature format in JavaScript file")
		return
	}

	fmt.Println("✓ JavaScript-generated schema loaded")

	// Load JavaScript well-known response
	wellKnownData, err := loadJSONFile(jsWellKnownFile)
	if err != nil {
		log.Printf("Failed to load JavaScript well-known file: %v", err)
		return
	}

	publicKeyPEM, ok := wellKnownData["public_key_pem"].(string)
	if !ok {
		log.Printf("Invalid public key in JavaScript well-known file")
		return
	}

	// Verify the JavaScript signature using Go implementation
	fmt.Println("\n2. Verifying JavaScript signature with Go implementation...")

	schemaHash, err := utils.CalculateSchemaHash(schema)
	if err != nil {
		log.Printf("Failed to calculate schema hash: %v", err)
		return
	}

	valid, err := utils.VerifySignatureOnly(schemaHash, signature, publicKeyPEM)
	if err != nil {
		log.Printf("Failed to verify signature: %v", err)
		return
	}

	if valid {
		fmt.Println("✅ JavaScript signature verified successfully with Go!")
		fmt.Println("🔗 Cross-language compatibility confirmed: JavaScript → Go")
	} else {
		fmt.Println("❌ JavaScript signature verification failed")
	}
}

func demoGenerateForOtherLanguages() {
	fmt.Println("\n=== Generate Go Signatures for Other Languages ===")

	// Generate a key pair
	fmt.Println("1. Generating Go key pair...")
	keyManager := crypto.NewKeyManager()
	privateKey, err := keyManager.GenerateKeypair()
	if err != nil {
		log.Printf("Failed to generate key pair: %v", err)
		return
	}

	privateKeyPEM, err := keyManager.ExportPrivateKeyPEM(privateKey)
	if err != nil {
		log.Printf("Failed to export private key: %v", err)
		return
	}

	publicKeyPEM, err := keyManager.ExportPublicKeyPEM(&privateKey.PublicKey)
	if err != nil {
		log.Printf("Failed to export public key: %v", err)
		return
	}

	fmt.Println("✓ Go key pair generated")

	// Create a test schema
	fmt.Println("\n2. Creating test schema...")
	testSchema := map[string]interface{}{
		"name":        "cross_language_test",
		"description": "Test schema for cross-language compatibility",
		"parameters": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"message": map[string]interface{}{
					"type":        "string",
					"description": "Test message",
				},
				"timestamp": map[string]interface{}{
					"type":        "number",
					"description": "Unix timestamp",
				},
			},
			"required": []string{"message"},
		},
	}

	fmt.Println("✓ Test schema created")

	// Sign the schema with Go
	fmt.Println("\n3. Signing schema with Go implementation...")
	signingWorkflow, err := utils.NewSchemaSigningWorkflow(privateKeyPEM)
	if err != nil {
		log.Printf("Failed to create signing workflow: %v", err)
		return
	}

	signature, err := signingWorkflow.SignSchema(testSchema)
	if err != nil {
		log.Printf("Failed to sign schema: %v", err)
		return
	}

	fmt.Println("✓ Schema signed with Go")

	// Create well-known response
	fmt.Println("\n4. Creating .well-known response...")
	wellKnownResponse := utils.CreateWellKnownResponse(
		publicKeyPEM,
		"Go Cross-Language Test",
		"test@example.com",
		[]string{}, // No revoked keys
		"1.1",
	)

	fmt.Println("✓ .well-known response created")

	// Save files for other languages to verify
	fmt.Println("\n5. Saving files for cross-language verification...")

	// Save signed schema
	schemaWithSignature := map[string]interface{}{
		"schema":    testSchema,
		"signature": signature,
		"language":  "go",
		"timestamp": time.Now().Unix(),
	}

	schemaJSON, _ := json.MarshalIndent(schemaWithSignature, "", "  ")
	if err := os.WriteFile("go_demo_schema_signed.json", schemaJSON, 0644); err != nil {
		log.Printf("Failed to save signed schema: %v", err)
		return
	}

	// Save well-known response
	wellKnownJSON, _ := json.MarshalIndent(wellKnownResponse, "", "  ")
	if err := os.WriteFile("go_demo_well_known.json", wellKnownJSON, 0644); err != nil {
		log.Printf("Failed to save well-known response: %v", err)
		return
	}

	// Save private key for reference (in real use, keep secure!)
	if err := os.WriteFile("go_demo_private_key.pem", []byte(privateKeyPEM), 0600); err != nil {
		log.Printf("Failed to save private key: %v", err)
		return
	}

	fmt.Println("✓ Files saved for cross-language verification:")
	fmt.Println("  - go_demo_schema_signed.json")
	fmt.Println("  - go_demo_well_known.json")
	fmt.Println("  - go_demo_private_key.pem")

	// Verify our own signature as a sanity check
	fmt.Println("\n6. Self-verification test...")
	schemaHash, err := utils.CalculateSchemaHash(testSchema)
	if err != nil {
		log.Printf("Failed to calculate schema hash: %v", err)
		return
	}

	valid, err := utils.VerifySignatureOnly(schemaHash, signature, publicKeyPEM)
	if err != nil {
		log.Printf("Failed to verify own signature: %v", err)
		return
	}

	if valid {
		fmt.Println("✅ Go self-verification successful")
		fmt.Println("🔗 Files ready for Python and JavaScript verification")
	} else {
		fmt.Println("❌ Go self-verification failed")
	}

	// Display verification instructions
	fmt.Println("\n7. Verification instructions for other languages:")
	fmt.Println("   Python: Use python/examples/client_verification.py with go_demo_* files")
	fmt.Println("   JavaScript: Use javascript/examples/client.js with go_demo_* files")
}

func loadJSONFile(filename string) (map[string]interface{}, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return result, nil
}
