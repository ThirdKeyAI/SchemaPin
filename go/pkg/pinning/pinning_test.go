package pinning

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ThirdKeyAi/schemapin/go/pkg/discovery"
	"github.com/ThirdKeyAi/schemapin/go/pkg/interactive"
)

// Mock interactive handler for testing
type mockInteractiveHandler struct {
	decision interactive.UserDecision
	err      error
}

func (m *mockInteractiveHandler) PromptUser(context *interactive.PromptContext) (interactive.UserDecision, error) {
	return m.decision, m.err
}

func (m *mockInteractiveHandler) DisplayKeyInfo(keyInfo *interactive.KeyInfo) string {
	return fmt.Sprintf("Key: %s", keyInfo.Fingerprint)
}

func (m *mockInteractiveHandler) DisplaySecurityWarning(warning string) {
	// Mock implementation
}

func createTempDB(t *testing.T) string {
	tmpDir := t.TempDir()
	return filepath.Join(tmpDir, "test_pinning.db")
}

func TestNewKeyPinning(t *testing.T) {
	dbPath := createTempDB(t)
	defer os.Remove(dbPath)

	handler := &mockInteractiveHandler{decision: interactive.UserDecisionAccept}
	pinning, err := NewKeyPinning(dbPath, PinningModeInteractive, handler)
	if err != nil {
		t.Fatalf("Failed to create KeyPinning: %v", err)
	}
	defer pinning.Close()

	if pinning.dbPath != dbPath {
		t.Errorf("Expected dbPath %s, got %s", dbPath, pinning.dbPath)
	}

	if pinning.mode != PinningModeInteractive {
		t.Errorf("Expected mode %s, got %s", PinningModeInteractive, pinning.mode)
	}

	if pinning.interactiveManager == nil {
		t.Errorf("Expected interactive manager to be set")
	}
}

func TestNewKeyPinningDefaultPath(t *testing.T) {
	handler := &mockInteractiveHandler{decision: interactive.UserDecisionAccept}

	// Use a temporary directory for the test
	tmpDir := t.TempDir()
	defaultPath := filepath.Join(tmpDir, ".schemapin", "pinned_keys.db")

	// Create the directory structure
	err := os.MkdirAll(filepath.Dir(defaultPath), 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	pinning, err := NewKeyPinning(defaultPath, PinningModeAutomatic, handler)
	if err != nil {
		t.Fatalf("Failed to create KeyPinning with default path: %v", err)
	}
	defer pinning.Close()

	if pinning.dbPath == "" {
		t.Errorf("Expected default dbPath to be set")
	}
}

func TestPinKey(t *testing.T) {
	dbPath := createTempDB(t)
	defer os.Remove(dbPath)

	pinning, err := NewKeyPinning(dbPath, PinningModeAutomatic, nil)
	if err != nil {
		t.Fatalf("Failed to create KeyPinning: %v", err)
	}
	defer pinning.Close()

	toolID := "test-tool"
	publicKeyPEM := "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----"
	domain := "example.com"
	developerName := "Test Developer"

	err = pinning.PinKey(toolID, publicKeyPEM, domain, developerName)
	if err != nil {
		t.Fatalf("Failed to pin key: %v", err)
	}

	// Verify key was pinned
	if !pinning.IsKeyPinned(toolID) {
		t.Errorf("Expected key to be pinned")
	}

	// Verify we can retrieve the key
	retrievedKey, err := pinning.GetPinnedKey(toolID)
	if err != nil {
		t.Fatalf("Failed to get pinned key: %v", err)
	}

	if retrievedKey != publicKeyPEM {
		t.Errorf("Expected key %s, got %s", publicKeyPEM, retrievedKey)
	}
}

func TestGetPinnedKeyNotFound(t *testing.T) {
	dbPath := createTempDB(t)
	defer os.Remove(dbPath)

	pinning, err := NewKeyPinning(dbPath, PinningModeAutomatic, nil)
	if err != nil {
		t.Fatalf("Failed to create KeyPinning: %v", err)
	}
	defer pinning.Close()

	key, err := pinning.GetPinnedKey("nonexistent-tool")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if key != "" {
		t.Errorf("Expected empty key for nonexistent tool, got %s", key)
	}

	if pinning.IsKeyPinned("nonexistent-tool") {
		t.Errorf("Expected key not to be pinned")
	}
}

func TestUpdateLastVerified(t *testing.T) {
	dbPath := createTempDB(t)
	defer os.Remove(dbPath)

	pinning, err := NewKeyPinning(dbPath, PinningModeAutomatic, nil)
	if err != nil {
		t.Fatalf("Failed to create KeyPinning: %v", err)
	}
	defer pinning.Close()

	toolID := "test-tool"
	publicKeyPEM := "test-key"
	domain := "example.com"

	// Pin a key first
	err = pinning.PinKey(toolID, publicKeyPEM, domain, "Test Developer")
	if err != nil {
		t.Fatalf("Failed to pin key: %v", err)
	}

	// Update last verified
	err = pinning.UpdateLastVerified(toolID)
	if err != nil {
		t.Fatalf("Failed to update last verified: %v", err)
	}

	// Verify the timestamp was updated
	keyInfo, err := pinning.GetKeyInfo(toolID)
	if err != nil {
		t.Fatalf("Failed to get key info: %v", err)
	}

	if keyInfo.LastVerified.IsZero() {
		t.Errorf("Expected last verified timestamp to be set")
	}
}

func TestUpdateLastVerifiedNotFound(t *testing.T) {
	dbPath := createTempDB(t)
	defer os.Remove(dbPath)

	pinning, err := NewKeyPinning(dbPath, PinningModeAutomatic, nil)
	if err != nil {
		t.Fatalf("Failed to create KeyPinning: %v", err)
	}
	defer pinning.Close()

	err = pinning.UpdateLastVerified("nonexistent-tool")
	if err == nil {
		t.Errorf("Expected error for nonexistent tool")
	}
}

func TestDomainPolicies(t *testing.T) {
	dbPath := createTempDB(t)
	defer os.Remove(dbPath)

	pinning, err := NewKeyPinning(dbPath, PinningModeAutomatic, nil)
	if err != nil {
		t.Fatalf("Failed to create KeyPinning: %v", err)
	}
	defer pinning.Close()

	domain := "example.com"

	// Test default policy
	policy := pinning.GetDomainPolicy(domain)
	if policy != PinningPolicyDefault {
		t.Errorf("Expected default policy, got %s", policy)
	}

	// Set a policy
	err = pinning.SetDomainPolicy(domain, PinningPolicyAlwaysTrust)
	if err != nil {
		t.Fatalf("Failed to set domain policy: %v", err)
	}

	// Verify policy was set
	policy = pinning.GetDomainPolicy(domain)
	if policy != PinningPolicyAlwaysTrust {
		t.Errorf("Expected always trust policy, got %s", policy)
	}

	// Test other policies
	policies := []PinningPolicy{
		PinningPolicyNeverTrust,
		PinningPolicyInteractiveOnly,
		PinningPolicyDefault,
	}

	for _, testPolicy := range policies {
		err = pinning.SetDomainPolicy(domain, testPolicy)
		if err != nil {
			t.Fatalf("Failed to set policy %s: %v", testPolicy, err)
		}

		retrievedPolicy := pinning.GetDomainPolicy(domain)
		if retrievedPolicy != testPolicy {
			t.Errorf("Expected policy %s, got %s", testPolicy, retrievedPolicy)
		}
	}
}

func TestListPinnedKeys(t *testing.T) {
	dbPath := createTempDB(t)
	defer os.Remove(dbPath)

	pinning, err := NewKeyPinning(dbPath, PinningModeAutomatic, nil)
	if err != nil {
		t.Fatalf("Failed to create KeyPinning: %v", err)
	}
	defer pinning.Close()

	// Initially should be empty
	keys, err := pinning.ListPinnedKeys()
	if err != nil {
		t.Fatalf("Failed to list keys: %v", err)
	}

	if len(keys) != 0 {
		t.Errorf("Expected 0 keys, got %d", len(keys))
	}

	// Pin some keys
	testKeys := []struct {
		toolID        string
		domain        string
		developerName string
	}{
		{"tool1", "example.com", "Developer 1"},
		{"tool2", "test.com", "Developer 2"},
		{"tool3", "example.com", "Developer 1"},
	}

	for _, tk := range testKeys {
		err = pinning.PinKey(tk.toolID, "test-key-"+tk.toolID, tk.domain, tk.developerName)
		if err != nil {
			t.Fatalf("Failed to pin key %s: %v", tk.toolID, err)
		}
	}

	// List keys
	keys, err = pinning.ListPinnedKeys()
	if err != nil {
		t.Fatalf("Failed to list keys: %v", err)
	}

	if len(keys) != len(testKeys) {
		t.Errorf("Expected %d keys, got %d", len(testKeys), len(keys))
	}

	// Verify key information
	for _, key := range keys {
		toolID, ok := key["tool_id"].(string)
		if !ok {
			t.Errorf("Expected tool_id to be string")
			continue
		}

		domain, ok := key["domain"].(string)
		if !ok {
			t.Errorf("Expected domain to be string")
			continue
		}

		developerName, ok := key["developer_name"].(string)
		if !ok {
			t.Errorf("Expected developer_name to be string")
			continue
		}

		// Find matching test key
		found := false
		for _, tk := range testKeys {
			if tk.toolID == toolID && tk.domain == domain && tk.developerName == developerName {
				found = true
				break
			}
		}

		if !found {
			t.Errorf("Unexpected key in list: %s", toolID)
		}
	}
}

func TestRemovePinnedKey(t *testing.T) {
	dbPath := createTempDB(t)
	defer os.Remove(dbPath)

	pinning, err := NewKeyPinning(dbPath, PinningModeAutomatic, nil)
	if err != nil {
		t.Fatalf("Failed to create KeyPinning: %v", err)
	}
	defer pinning.Close()

	toolID := "test-tool"
	publicKeyPEM := "test-key"
	domain := "example.com"

	// Pin a key
	err = pinning.PinKey(toolID, publicKeyPEM, domain, "Test Developer")
	if err != nil {
		t.Fatalf("Failed to pin key: %v", err)
	}

	// Verify it's pinned
	if !pinning.IsKeyPinned(toolID) {
		t.Errorf("Expected key to be pinned")
	}

	// Remove the key
	err = pinning.RemovePinnedKey(toolID)
	if err != nil {
		t.Fatalf("Failed to remove key: %v", err)
	}

	// Verify it's no longer pinned
	if pinning.IsKeyPinned(toolID) {
		t.Errorf("Expected key to be removed")
	}
}

func TestExportImportPinnedKeys(t *testing.T) {
	dbPath := createTempDB(t)
	defer os.Remove(dbPath)

	pinning, err := NewKeyPinning(dbPath, PinningModeAutomatic, nil)
	if err != nil {
		t.Fatalf("Failed to create KeyPinning: %v", err)
	}
	defer pinning.Close()

	// Pin some keys
	testKeys := []struct {
		toolID        string
		publicKeyPEM  string
		domain        string
		developerName string
	}{
		{"tool1", "key1", "example.com", "Developer 1"},
		{"tool2", "key2", "test.com", "Developer 2"},
	}

	for _, tk := range testKeys {
		err = pinning.PinKey(tk.toolID, tk.publicKeyPEM, tk.domain, tk.developerName)
		if err != nil {
			t.Fatalf("Failed to pin key %s: %v", tk.toolID, err)
		}
	}

	// Export keys
	exportData, err := pinning.ExportPinnedKeys()
	if err != nil {
		t.Fatalf("Failed to export keys: %v", err)
	}

	// Verify export data is valid JSON
	var exportedKeys []PinnedKeyInfo
	err = json.Unmarshal([]byte(exportData), &exportedKeys)
	if err != nil {
		t.Fatalf("Failed to parse exported JSON: %v", err)
	}

	if len(exportedKeys) != len(testKeys) {
		t.Errorf("Expected %d exported keys, got %d", len(testKeys), len(exportedKeys))
	}

	// Create new database for import test
	dbPath2 := createTempDB(t)
	defer os.Remove(dbPath2)

	pinning2, err := NewKeyPinning(dbPath2, PinningModeAutomatic, nil)
	if err != nil {
		t.Fatalf("Failed to create second KeyPinning: %v", err)
	}
	defer pinning2.Close()

	// Import keys
	imported, err := pinning2.ImportPinnedKeys(exportData, false)
	if err != nil {
		t.Fatalf("Failed to import keys: %v", err)
	}

	if imported != len(testKeys) {
		t.Errorf("Expected %d imported keys, got %d", len(testKeys), imported)
	}

	// Verify imported keys
	for _, tk := range testKeys {
		if !pinning2.IsKeyPinned(tk.toolID) {
			t.Errorf("Expected imported key %s to be pinned", tk.toolID)
		}

		retrievedKey, err := pinning2.GetPinnedKey(tk.toolID)
		if err != nil {
			t.Fatalf("Failed to get imported key %s: %v", tk.toolID, err)
		}

		if retrievedKey != tk.publicKeyPEM {
			t.Errorf("Expected imported key %s, got %s", tk.publicKeyPEM, retrievedKey)
		}
	}
}

func TestInteractivePinKeyAutomatic(t *testing.T) {
	dbPath := createTempDB(t)
	defer os.Remove(dbPath)

	pinning, err := NewKeyPinning(dbPath, PinningModeAutomatic, nil)
	if err != nil {
		t.Fatalf("Failed to create KeyPinning: %v", err)
	}
	defer pinning.Close()

	toolID := "test-tool"
	publicKeyPEM := "test-key"
	domain := "example.com"
	developerName := "Test Developer"

	// In automatic mode, should pin without prompts
	result, err := pinning.InteractivePinKey(toolID, publicKeyPEM, domain, developerName)
	if err != nil {
		t.Fatalf("Failed to interactive pin key: %v", err)
	}

	if !result {
		t.Errorf("Expected key to be pinned in automatic mode")
	}

	if !pinning.IsKeyPinned(toolID) {
		t.Errorf("Expected key to be pinned")
	}
}

func TestInteractivePinKeyWithMockServer(t *testing.T) {
	// Create mock server for .well-known endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := discovery.WellKnownResponse{
			SchemaVersion: "1.1",
			DeveloperName: "Test Developer",
			PublicKeyPEM:  "test-key",
			RevokedKeys:   []string{}, // No revoked keys
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	dbPath := createTempDB(t)
	defer os.Remove(dbPath)

	handler := &mockInteractiveHandler{decision: interactive.UserDecisionAccept}
	pinning, err := NewKeyPinning(dbPath, PinningModeInteractive, handler)
	if err != nil {
		t.Fatalf("Failed to create KeyPinning: %v", err)
	}
	defer pinning.Close()

	toolID := "test-tool"
	publicKeyPEM := "test-key"
	domain := server.URL[7:] // Remove "http://" for domain
	developerName := "Test Developer"

	result, err := pinning.InteractivePinKey(toolID, publicKeyPEM, domain, developerName)
	if err != nil {
		t.Fatalf("Failed to interactive pin key: %v", err)
	}

	if !result {
		t.Errorf("Expected key to be accepted")
	}

	if !pinning.IsKeyPinned(toolID) {
		t.Errorf("Expected key to be pinned")
	}
}

func TestInteractivePinKeyReject(t *testing.T) {
	dbPath := createTempDB(t)
	defer os.Remove(dbPath)

	handler := &mockInteractiveHandler{decision: interactive.UserDecisionReject}
	pinning, err := NewKeyPinning(dbPath, PinningModeInteractive, handler)
	if err != nil {
		t.Fatalf("Failed to create KeyPinning: %v", err)
	}
	defer pinning.Close()

	toolID := "test-tool"
	publicKeyPEM := "test-key"
	domain := "example.com"
	developerName := "Test Developer"

	result, err := pinning.InteractivePinKey(toolID, publicKeyPEM, domain, developerName)
	if err != nil {
		t.Fatalf("Failed to interactive pin key: %v", err)
	}

	if result {
		t.Errorf("Expected key to be rejected")
	}

	if pinning.IsKeyPinned(toolID) {
		t.Errorf("Expected key not to be pinned")
	}
}

func TestDomainPolicyNeverTrust(t *testing.T) {
	dbPath := createTempDB(t)
	defer os.Remove(dbPath)

	pinning, err := NewKeyPinning(dbPath, PinningModeInteractive, nil)
	if err != nil {
		t.Fatalf("Failed to create KeyPinning: %v", err)
	}
	defer pinning.Close()

	domain := "untrusted.com"
	toolID := "test-tool"
	publicKeyPEM := "test-key"

	// Set never trust policy
	err = pinning.SetDomainPolicy(domain, PinningPolicyNeverTrust)
	if err != nil {
		t.Fatalf("Failed to set domain policy: %v", err)
	}

	// Try to pin key - should be rejected due to policy
	result, err := pinning.InteractivePinKey(toolID, publicKeyPEM, domain, "Test Developer")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result {
		t.Errorf("Expected key to be rejected due to never trust policy")
	}

	if pinning.IsKeyPinned(toolID) {
		t.Errorf("Expected key not to be pinned")
	}
}

func TestDomainPolicyAlwaysTrust(t *testing.T) {
	dbPath := createTempDB(t)
	defer os.Remove(dbPath)

	pinning, err := NewKeyPinning(dbPath, PinningModeInteractive, nil)
	if err != nil {
		t.Fatalf("Failed to create KeyPinning: %v", err)
	}
	defer pinning.Close()

	domain := "trusted.com"
	toolID := "test-tool"
	publicKeyPEM := "test-key"

	// Set always trust policy
	err = pinning.SetDomainPolicy(domain, PinningPolicyAlwaysTrust)
	if err != nil {
		t.Fatalf("Failed to set domain policy: %v", err)
	}

	// Try to pin key - should be accepted due to policy
	result, err := pinning.InteractivePinKey(toolID, publicKeyPEM, domain, "Test Developer")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !result {
		t.Errorf("Expected key to be accepted due to always trust policy")
	}

	if !pinning.IsKeyPinned(toolID) {
		t.Errorf("Expected key to be pinned")
	}
}

func TestKeyChangeScenario(t *testing.T) {
	dbPath := createTempDB(t)
	defer os.Remove(dbPath)

	handler := &mockInteractiveHandler{decision: interactive.UserDecisionAccept}
	pinning, err := NewKeyPinning(dbPath, PinningModeInteractive, handler)
	if err != nil {
		t.Fatalf("Failed to create KeyPinning: %v", err)
	}
	defer pinning.Close()

	toolID := "test-tool"
	originalKey := "original-key"
	newKey := "new-key"
	domain := "example.com"
	developerName := "Test Developer"

	// Pin original key
	result, err := pinning.InteractivePinKey(toolID, originalKey, domain, developerName)
	if err != nil {
		t.Fatalf("Failed to pin original key: %v", err)
	}

	if !result {
		t.Errorf("Expected original key to be pinned")
	}

	// Try to pin new key (should trigger key change scenario)
	result, err = pinning.InteractivePinKey(toolID, newKey, domain, developerName)
	if err != nil {
		t.Fatalf("Failed to handle key change: %v", err)
	}

	if !result {
		t.Errorf("Expected new key to be accepted")
	}

	// Verify new key is pinned
	retrievedKey, err := pinning.GetPinnedKey(toolID)
	if err != nil {
		t.Fatalf("Failed to get pinned key: %v", err)
	}

	if retrievedKey != newKey {
		t.Errorf("Expected new key %s, got %s", newKey, retrievedKey)
	}
}

func TestSameKeyUpdateVerification(t *testing.T) {
	dbPath := createTempDB(t)
	defer os.Remove(dbPath)

	pinning, err := NewKeyPinning(dbPath, PinningModeAutomatic, nil)
	if err != nil {
		t.Fatalf("Failed to create KeyPinning: %v", err)
	}
	defer pinning.Close()

	toolID := "test-tool"
	publicKeyPEM := "test-key"
	domain := "example.com"
	developerName := "Test Developer"

	// Pin key first time
	result, err := pinning.InteractivePinKey(toolID, publicKeyPEM, domain, developerName)
	if err != nil {
		t.Fatalf("Failed to pin key: %v", err)
	}

	if !result {
		t.Errorf("Expected key to be pinned")
	}

	// Get initial key info
	keyInfo1, err := pinning.GetKeyInfo(toolID)
	if err != nil {
		t.Fatalf("Failed to get key info: %v", err)
	}

	// Wait a bit to ensure timestamp difference
	time.Sleep(10 * time.Millisecond)

	// Pin same key again (should update last verified)
	result, err = pinning.InteractivePinKey(toolID, publicKeyPEM, domain, developerName)
	if err != nil {
		t.Fatalf("Failed to re-pin same key: %v", err)
	}

	if !result {
		t.Errorf("Expected same key to be accepted")
	}

	// Get updated key info
	keyInfo2, err := pinning.GetKeyInfo(toolID)
	if err != nil {
		t.Fatalf("Failed to get updated key info: %v", err)
	}

	// Verify last verified was updated
	if !keyInfo2.LastVerified.After(keyInfo1.LastVerified) {
		t.Errorf("Expected last verified to be updated")
	}
}
