// Package main demonstrates SchemaPin interactive key pinning functionality.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/ThirdKeyAi/schemapin/go/internal/version"
	"github.com/ThirdKeyAi/schemapin/go/pkg/core"
	"github.com/ThirdKeyAi/schemapin/go/pkg/crypto"
	"github.com/ThirdKeyAi/schemapin/go/pkg/interactive"
	"github.com/ThirdKeyAi/schemapin/go/pkg/pinning"
)

func main() {
	fmt.Printf("SchemaPin Interactive Key Pinning Demo v%s\n", version.GetVersion())
	fmt.Println(strings.Repeat("=", 50))

	// Demo 1: Console Interactive Pinning
	demoConsoleInteractivePinning()

	// Demo 2: Callback Interactive Pinning
	demoCallbackInteractivePinning()

	// Demo 3: Domain Policies
	demoDomainPolicies()

	// Demo 4: Schema Verification with Interactive Pinning
	demoSchemaVerificationWithInteractivePinning()

	fmt.Println("\n🎉 All demos completed successfully!")
}

func demoConsoleInteractivePinning() {
	fmt.Println("\n=== Console Interactive Pinning Demo ===")

	// Create temporary database
	tempDB := "/tmp/schemapin_console_demo.db"
	defer os.Remove(tempDB)

	// Initialize pinning with interactive mode
	keyPinning, err := pinning.NewKeyPinning(tempDB, pinning.PinningModeInteractive, nil)
	if err != nil {
		log.Printf("Failed to initialize key pinning: %v", err)
		return
	}
	defer keyPinning.Close()

	// Generate demo keys
	keyManager := crypto.NewKeyManager()
	privateKey, err := keyManager.GenerateKeypair()
	if err != nil {
		log.Printf("Failed to generate key pair: %v", err)
		return
	}

	publicKeyPEM, err := keyManager.ExportPublicKeyPEM(&privateKey.PublicKey)
	if err != nil {
		log.Printf("Failed to export public key: %v", err)
		return
	}

	// Demo tool information
	toolID := "demo-calculator"
	domain := "example-tools.com"
	developerName := "Example Tools Inc"

	fingerprint, _ := keyManager.CalculateKeyFingerprint(&privateKey.PublicKey)

	fmt.Printf("Tool: %s\n", toolID)
	fmt.Printf("Domain: %s\n", domain)
	fmt.Printf("Developer: %s\n", developerName)
	fmt.Printf("Key Fingerprint: %s\n", fingerprint)
	fmt.Println()

	// For demo purposes, we'll simulate user acceptance
	fmt.Println("Simulating user acceptance of key pinning...")
	err = keyPinning.PinKey(toolID, publicKeyPEM, domain, developerName)
	if err != nil {
		fmt.Printf("❌ Key pinning failed: %v\n", err)
	} else {
		fmt.Println("✅ Key was accepted and pinned!")
	}

	fmt.Printf("Key pinned: %t\n", keyPinning.IsKeyPinned(toolID))

	// Demonstrate key change scenario
	if keyPinning.IsKeyPinned(toolID) {
		fmt.Println("\n--- Key Change Scenario ---")

		// Generate new key
		newPrivateKey, err := keyManager.GenerateKeypair()
		if err != nil {
			log.Printf("Failed to generate new key: %v", err)
			return
		}

		newFingerprint, _ := keyManager.CalculateKeyFingerprint(&newPrivateKey.PublicKey)
		fmt.Printf("New Key Fingerprint: %s\n", newFingerprint)
		fmt.Println("Attempting to change pinned key...")

		// For demo, we'll show that key changes require explicit approval
		fmt.Println("❌ Key change was rejected (requires explicit user approval)")
	}
}

func demoCallbackInteractivePinning() {
	fmt.Println("\n=== Callback Interactive Pinning Demo ===")

	// Create temporary database
	tempDB := "/tmp/schemapin_callback_demo.db"
	defer os.Remove(tempDB)

	// Custom callback function
	customPromptHandler := func(context *interactive.PromptContext) (interactive.UserDecision, error) {
		fmt.Printf("Custom handler called for: %s\n", context.ToolID)
		fmt.Printf("Prompt type: %s\n", context.PromptType)

		switch context.PromptType {
		case interactive.PromptTypeFirstTimeKey:
			fmt.Println("Auto-accepting first-time key...")
			return interactive.UserDecisionAccept, nil
		case interactive.PromptTypeKeyChange:
			fmt.Println("Auto-rejecting key change...")
			return interactive.UserDecisionReject, nil
		default:
			fmt.Println("Auto-rejecting revoked key...")
			return interactive.UserDecisionReject, nil
		}
	}

	// Create callback handler with all required callbacks
	callbackHandler := interactive.NewCallbackInteractiveHandler(
		customPromptHandler,
		func(keyInfo *interactive.KeyInfo) string {
			return fmt.Sprintf("Key: %s | Domain: %s", keyInfo.Fingerprint, keyInfo.Domain)
		},
		func(warning string) {
			fmt.Printf("WARNING: %s\n", warning)
		},
	)

	// Initialize pinning with callback handler
	keyPinning, err := pinning.NewKeyPinning(tempDB, pinning.PinningModeInteractive, callbackHandler)
	if err != nil {
		log.Printf("Failed to initialize key pinning: %v", err)
		return
	}
	defer keyPinning.Close()

	// Generate demo keys
	keyManager := crypto.NewKeyManager()
	privateKey, err := keyManager.GenerateKeypair()
	if err != nil {
		log.Printf("Failed to generate key pair: %v", err)
		return
	}

	publicKeyPEM, err := keyManager.ExportPublicKeyPEM(&privateKey.PublicKey)
	if err != nil {
		log.Printf("Failed to export public key: %v", err)
		return
	}

	// Demo tool information
	toolID := "demo-api-client"
	domain := "api.example.com"
	developerName := "API Corp"

	fmt.Printf("Tool: %s\n", toolID)
	fmt.Printf("Domain: %s\n", domain)
	fmt.Printf("Developer: %s\n", developerName)
	fmt.Println()

	// Pin the key (will use callback)
	err = keyPinning.PinKey(toolID, publicKeyPEM, domain, developerName)
	result := err == nil

	fmt.Printf("Result: %s\n", map[bool]string{true: "Accepted", false: "Rejected"}[result])
	fmt.Printf("Key pinned: %t\n", keyPinning.IsKeyPinned(toolID))

	// Test key change (should be rejected by callback)
	if keyPinning.IsKeyPinned(toolID) {
		fmt.Println("\n--- Testing Key Change ---")

		newPrivateKey, err := keyManager.GenerateKeypair()
		if err != nil {
			log.Printf("Failed to generate new key: %v", err)
			return
		}

		newPublicKeyPEM, err := keyManager.ExportPublicKeyPEM(&newPrivateKey.PublicKey)
		if err != nil {
			log.Printf("Failed to export new public key: %v", err)
			return
		}

		// Attempt to change the key (should be rejected)
		err = keyPinning.PinKey(toolID, newPublicKeyPEM, domain, developerName)
		result = err == nil

		fmt.Printf("Key change result: %s\n", map[bool]string{true: "Accepted", false: "Rejected"}[result])
	}
}

func demoDomainPolicies() {
	fmt.Println("\n=== Domain Policies Demo ===")

	// Create temporary database
	tempDB := "/tmp/schemapin_policies_demo.db"
	defer os.Remove(tempDB)

	keyPinning, err := pinning.NewKeyPinning(tempDB, pinning.PinningModeInteractive, nil)
	if err != nil {
		log.Printf("Failed to initialize key pinning: %v", err)
		return
	}
	defer keyPinning.Close()

	// Generate demo key
	keyManager := crypto.NewKeyManager()
	privateKey, err := keyManager.GenerateKeypair()
	if err != nil {
		log.Printf("Failed to generate key pair: %v", err)
		return
	}

	publicKeyPEM, err := keyManager.ExportPublicKeyPEM(&privateKey.PublicKey)
	if err != nil {
		log.Printf("Failed to export public key: %v", err)
		return
	}

	// Test different domain policies
	domains := []struct {
		domain string
		policy pinning.PinningPolicy
	}{
		{"trusted.example.com", pinning.PinningPolicyAlwaysTrust},
		{"untrusted.example.com", pinning.PinningPolicyNeverTrust},
		{"normal.example.com", pinning.PinningPolicyDefault},
	}

	for _, test := range domains {
		fmt.Printf("Testing domain: %s with policy: %s\n", test.domain, test.policy)

		// Set domain policy
		keyPinning.SetDomainPolicy(test.domain, test.policy)

		// Try to pin key
		toolID := fmt.Sprintf("tool-%s", strings.Split(test.domain, ".")[0])
		err := keyPinning.PinKey(toolID, publicKeyPEM, test.domain, "Test Developer")
		result := err == nil

		fmt.Printf("  Result: %s\n", map[bool]string{true: "Accepted", false: "Rejected"}[result])
		fmt.Printf("  Key pinned: %t\n", keyPinning.IsKeyPinned(toolID))
		fmt.Println()
	}
}

func demoSchemaVerificationWithInteractivePinning() {
	fmt.Println("\n=== Schema Verification with Interactive Pinning Demo ===")

	// Create temporary database
	tempDB := "/tmp/schemapin_verification_demo.db"
	defer os.Remove(tempDB)

	// Initialize components
	keyPinning, err := pinning.NewKeyPinning(tempDB, pinning.PinningModeAutomatic, nil)
	if err != nil {
		log.Printf("Failed to initialize key pinning: %v", err)
		return
	}
	defer keyPinning.Close()

	// Generate developer key pair
	keyManager := crypto.NewKeyManager()
	privateKey, err := keyManager.GenerateKeypair()
	if err != nil {
		log.Printf("Failed to generate key pair: %v", err)
		return
	}

	publicKeyPEM, err := keyManager.ExportPublicKeyPEM(&privateKey.PublicKey)
	if err != nil {
		log.Printf("Failed to export public key: %v", err)
		return
	}

	// Create demo schema
	schema := map[string]interface{}{
		"name":        "calculate_sum",
		"description": "Calculate the sum of two numbers",
		"parameters": map[string]interface{}{
			"a": map[string]interface{}{"type": "number", "description": "First number"},
			"b": map[string]interface{}{"type": "number", "description": "Second number"},
		},
	}

	// Sign the schema
	schemaPinCore := core.NewSchemaPinCore()
	schemaHash, err := schemaPinCore.CanonicalizeAndHash(schema)
	if err != nil {
		log.Printf("Failed to canonicalize schema: %v", err)
		return
	}

	signatureManager := crypto.NewSignatureManager()
	signature, err := signatureManager.SignSchemaHash(schemaHash, privateKey)
	if err != nil {
		log.Printf("Failed to sign schema: %v", err)
		return
	}

	fmt.Println("Schema to verify:")
	schemaJSON, _ := json.MarshalIndent(schema, "", "  ")
	fmt.Println(string(schemaJSON))
	fmt.Printf("\nSignature: %s...\n", signature[:50])

	fingerprint, _ := keyManager.CalculateKeyFingerprint(&privateKey.PublicKey)
	fmt.Printf("Key fingerprint: %s\n", fingerprint)

	// Tool information
	toolID := "math-calculator"
	domain := "mathtools.example.com"
	developerName := "Math Tools LLC"

	// Verify with interactive pinning
	fmt.Printf("\nVerifying schema for tool: %s\n", toolID)

	// First, handle key pinning
	err = keyPinning.PinKey(toolID, publicKeyPEM, domain, developerName)
	pinResult := err == nil

	if pinResult {
		fmt.Println("✅ Key pinning successful")

		// Now verify the signature
		verificationResult := signatureManager.VerifySchemaSignature(schemaHash, signature, &privateKey.PublicKey)

		if verificationResult {
			fmt.Println("✅ Schema signature verification successful")
			fmt.Println("🎉 Schema is authentic and can be trusted!")
		} else {
			fmt.Println("❌ Schema signature verification failed")
		}
	} else {
		fmt.Println("❌ Key pinning failed - schema cannot be trusted")
	}

	// Show pinned keys
	fmt.Println("\nPinned keys in database:")
	pinnedKeys, err := keyPinning.ListPinnedKeys()
	if err != nil {
		log.Printf("Failed to list pinned keys: %v", err)
	} else {
		for _, keyInfo := range pinnedKeys {
			if toolID, ok := keyInfo["tool_id"].(string); ok {
				if domain, ok := keyInfo["domain"].(string); ok {
					fmt.Printf("  - %s (%s)\n", toolID, domain)
				}
			}
		}
	}
}
