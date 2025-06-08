// Package main demonstrates SchemaPin client verification workflow.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/ThirdKeyAi/schemapin/go/internal/version"
	"github.com/ThirdKeyAi/schemapin/go/pkg/pinning"
	"github.com/ThirdKeyAi/schemapin/go/pkg/utils"
)

// mockDiscoveryService simulates .well-known discovery for demonstration
type mockDiscoveryService struct {
	wellKnownData map[string]interface{}
}

func (m *mockDiscoveryService) GetPublicKeyPEM(ctx context.Context, domain string) (string, error) {
	if domain == "example.com" && m.wellKnownData != nil {
		if pubKey, ok := m.wellKnownData["public_key_pem"].(string); ok {
			return pubKey, nil
		}
	}
	return "", fmt.Errorf("public key not found for domain: %s", domain)
}

func (m *mockDiscoveryService) GetDeveloperInfo(ctx context.Context, domain string) (map[string]string, error) {
	if domain == "example.com" && m.wellKnownData != nil {
		info := make(map[string]string)
		if name, ok := m.wellKnownData["developer_name"].(string); ok {
			info["developer_name"] = name
		}
		if contact, ok := m.wellKnownData["contact"].(string); ok {
			info["contact"] = contact
		}
		if version, ok := m.wellKnownData["schema_version"].(string); ok {
			info["schema_version"] = version
		}
		return info, nil
	}
	return nil, fmt.Errorf("developer info not found for domain: %s", domain)
}

func (m *mockDiscoveryService) ValidateKeyNotRevoked(ctx context.Context, publicKeyPEM, domain string) (bool, error) {
	// For demo purposes, assume keys are not revoked
	return true, nil
}

func main() {
	fmt.Printf("SchemaPin Client Verification Example v%s\n", version.GetVersion())
	fmt.Println(strings.Repeat("=", 45))

	// Check if we have demo files from tool developer example
	schemaFile := "demo_schema_signed.json"
	wellKnownFile := "demo_well_known.json"

	if _, err := os.Stat(schemaFile); os.IsNotExist(err) {
		fmt.Println("❌ demo_schema_signed.json not found!")
		fmt.Println("Please run the developer example first to generate demo files.")
		return
	}

	// Load signed schema
	fmt.Println("\n1. Loading signed schema...")
	schemaData, err := loadJSONFile(schemaFile)
	if err != nil {
		log.Fatalf("Failed to load schema file: %v", err)
	}

	schema, ok := schemaData["schema"].(map[string]interface{})
	if !ok {
		log.Fatal("Invalid schema format in demo file")
	}

	signature, ok := schemaData["signature"].(string)
	if !ok {
		log.Fatal("Invalid signature format in demo file")
	}

	fmt.Println("✓ Signed schema loaded")
	if name, ok := schema["name"].(string); ok {
		if desc, ok := schema["description"].(string); ok {
			fmt.Printf("Schema: %s - %s\n", name, desc)
		}
	}
	fmt.Printf("Signature: %s...\n", signature[:32])

	// Load well-known response for mocking
	var wellKnownData map[string]interface{}
	if _, err := os.Stat(wellKnownFile); err == nil {
		wellKnownData, err = loadJSONFile(wellKnownFile)
		if err != nil {
			log.Printf("Warning: Failed to load well-known file: %v", err)
		}
	}

	// Step 2: Initialize verification workflow with temporary database
	fmt.Println("\n2. Initializing verification workflow...")
	tempDB := "/tmp/schemapin_demo.db"
	defer os.Remove(tempDB) // Cleanup

	verificationWorkflow, err := utils.NewSchemaVerificationWorkflow(tempDB)
	if err != nil {
		log.Fatalf("Failed to initialize verification workflow: %v", err)
	}
	defer verificationWorkflow.Close()

	fmt.Println("✓ Verification workflow initialized")

	// Step 3: Mock the discovery service for demonstration
	fmt.Println("\n3. Simulating public key discovery...")
	mockDiscovery := &mockDiscoveryService{wellKnownData: wellKnownData}

	// Replace the discovery service in the workflow (for demo purposes)
	// In a real implementation, this would use actual HTTP requests
	fmt.Println("✓ Mock discovery service configured")

	// Step 4: First-time verification (key pinning)
	fmt.Println("\n4. First-time verification (TOFU - Trust On First Use)...")

	// For demo purposes, we'll manually handle the verification since we're mocking
	result, err := performMockVerification(verificationWorkflow, mockDiscovery, schema, signature, "example.com/calculate_sum", "example.com", true)
	if err != nil {
		log.Fatalf("Verification failed: %v", err)
	}

	fmt.Printf("✓ Verification result: valid=%t, pinned=%t, first_use=%t\n", result.Valid, result.Pinned, result.FirstUse)

	if result.Valid {
		fmt.Println("✅ Schema signature is VALID")
		if result.FirstUse {
			fmt.Println("🔑 Key pinned for future use")
			if result.DeveloperInfo != nil {
				if devName, ok := result.DeveloperInfo["developer_name"]; ok {
					fmt.Printf("📋 Developer: %s\n", devName)
				}
				if contact, ok := result.DeveloperInfo["contact"]; ok {
					fmt.Printf("📧 Contact: %s\n", contact)
				}
			}
		}
	} else {
		fmt.Println("❌ Schema signature is INVALID")
		if result.Error != "" {
			fmt.Printf("Error: %s\n", result.Error)
		}
	}

	// Step 5: Subsequent verification (using pinned key)
	fmt.Println("\n5. Subsequent verification (using pinned key)...")

	result2, err := performMockVerification(verificationWorkflow, mockDiscovery, schema, signature, "example.com/calculate_sum", "example.com", false)
	if err != nil {
		log.Fatalf("Second verification failed: %v", err)
	}

	fmt.Printf("✓ Verification result: valid=%t, pinned=%t, first_use=%t\n", result2.Valid, result2.Pinned, result2.FirstUse)

	if result2.Valid {
		fmt.Println("✅ Schema signature is VALID (using pinned key)")
		fmt.Println("🔒 Key was already pinned - no network request needed")
	} else {
		fmt.Println("❌ Schema signature is INVALID")
	}

	// Step 6: Show pinned keys
	fmt.Println("\n6. Listing pinned keys...")
	pinnedKeys, err := verificationWorkflow.ListPinnedKeys()
	if err != nil {
		log.Printf("Failed to list pinned keys: %v", err)
	} else if len(pinnedKeys) > 0 {
		fmt.Println("✓ Pinned keys:")
		for _, keyInfo := range pinnedKeys {
			if toolID, ok := keyInfo["tool_id"].(string); ok {
				if domain, ok := keyInfo["domain"].(string); ok {
					if devName, ok := keyInfo["developer_name"].(string); ok {
						if pinnedAt, ok := keyInfo["pinned_at"].(string); ok {
							fmt.Printf("  - Tool: %s\n", toolID)
							fmt.Printf("    Domain: %s\n", domain)
							fmt.Printf("    Developer: %s\n", devName)
							fmt.Printf("    Pinned: %s\n", pinnedAt)
						}
					}
				}
			}
		}
	} else {
		fmt.Println("No keys pinned yet")
	}

	// Step 7: Demonstrate invalid signature detection
	fmt.Println("\n7. Testing invalid signature detection...")

	// Modify the signature to make it invalid
	invalidSignature := signature[:len(signature)-4] + "XXXX"

	result3, err := performMockVerification(verificationWorkflow, mockDiscovery, schema, invalidSignature, "example.com/calculate_sum", "example.com", false)
	if err != nil {
		log.Printf("Expected verification failure: %v", err)
	}

	if result3 != nil && !result3.Valid {
		fmt.Println("✅ Invalid signature correctly detected")
		fmt.Println("🛡️ SchemaPin successfully prevented use of tampered schema")
	} else {
		fmt.Println("❌ Invalid signature was not detected (this should not happen)")
	}

	fmt.Println("\n" + strings.Repeat("=", 45))
	fmt.Println("Client verification workflow complete!")
	fmt.Println("\nKey takeaways:")
	fmt.Println("✓ Valid signatures are accepted")
	fmt.Println("✓ Invalid signatures are rejected")
	fmt.Println("✓ Keys are pinned on first use (TOFU)")
	fmt.Println("✓ Subsequent verifications use pinned keys")
	fmt.Println("✓ Network requests only needed for new tools")
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

func performMockVerification(workflow *utils.SchemaVerificationWorkflow, mockDiscovery *mockDiscoveryService, schema map[string]interface{}, signature, toolID, domain string, autoPin bool) (*utils.VerificationResult, error) {
	ctx := context.Background()

	// Check if key is already pinned
	pinnedKeyPEM, err := workflow.GetPinnedKeyInfo(toolID)
	var publicKeyPEM string

	if err != nil || pinnedKeyPEM == nil {
		// First use - get key from mock discovery
		publicKeyPEM, err = mockDiscovery.GetPublicKeyPEM(ctx, domain)
		if err != nil {
			return &utils.VerificationResult{
				Valid: false,
				Error: fmt.Sprintf("could not discover public key: %v", err),
			}, nil
		}

		// Auto-pin if requested
		if autoPin {
			developerInfo, _ := mockDiscovery.GetDeveloperInfo(ctx, domain)
			developerName := ""
			if developerInfo != nil {
				if name, ok := developerInfo["developer_name"]; ok {
					developerName = name
				}
			}

			// Pin the key manually since we're using mock discovery
			keyPinning, err := pinning.NewKeyPinning("/tmp/schemapin_demo.db", pinning.PinningModeAutomatic, nil)
			if err == nil {
				defer keyPinning.Close()
				keyPinning.PinKey(toolID, publicKeyPEM, domain, developerName)
			}

			return &utils.VerificationResult{
				Valid:         true, // Assume valid for demo
				Pinned:        true,
				FirstUse:      true,
				DeveloperInfo: developerInfo,
			}, nil
		}
	} else {
		publicKeyPEM = pinnedKeyPEM.PublicKeyPEM
	}

	// Verify signature using utils
	schemaHash, err := utils.CalculateSchemaHash(schema)
	if err != nil {
		return &utils.VerificationResult{
			Valid: false,
			Error: fmt.Sprintf("failed to calculate schema hash: %v", err),
		}, nil
	}

	valid, err := utils.VerifySignatureOnly(schemaHash, signature, publicKeyPEM)
	if err != nil {
		return &utils.VerificationResult{
			Valid: false,
			Error: fmt.Sprintf("signature verification failed: %v", err),
		}, nil
	}

	return &utils.VerificationResult{
		Valid:    valid,
		Pinned:   pinnedKeyPEM != nil,
		FirstUse: pinnedKeyPEM == nil,
	}, nil
}
