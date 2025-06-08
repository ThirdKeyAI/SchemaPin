package interactive

import (
	"strings"
	"testing"
	"time"

	"github.com/ThirdKeyAi/schemapin/go/pkg/crypto"
)

// MockInteractiveHandler for testing
type MockInteractiveHandler struct {
	decision UserDecision
	err      error
}

func (m *MockInteractiveHandler) PromptUser(context *PromptContext) (UserDecision, error) {
	return m.decision, m.err
}

func (m *MockInteractiveHandler) DisplayKeyInfo(keyInfo *KeyInfo) string {
	return "mock key info"
}

func (m *MockInteractiveHandler) DisplaySecurityWarning(warning string) {
	// Mock implementation
}

func TestPromptType(t *testing.T) {
	tests := []struct {
		name     string
		prompt   PromptType
		expected string
	}{
		{"FirstTimeKey", PromptTypeFirstTimeKey, "first_time_key"},
		{"KeyChange", PromptTypeKeyChange, "key_change"},
		{"RevokedKey", PromptTypeRevokedKey, "revoked_key"},
		{"ExpiredKey", PromptTypeExpiredKey, "expired_key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.prompt) != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, string(tt.prompt))
			}
		})
	}
}

func TestUserDecision(t *testing.T) {
	tests := []struct {
		name     string
		decision UserDecision
		expected string
	}{
		{"Accept", UserDecisionAccept, "accept"},
		{"Reject", UserDecisionReject, "reject"},
		{"AlwaysTrust", UserDecisionAlwaysTrust, "always_trust"},
		{"NeverTrust", UserDecisionNeverTrust, "never_trust"},
		{"TemporaryAccept", UserDecisionTemporaryAccept, "temporary_accept"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.decision) != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, string(tt.decision))
			}
		})
	}
}

func TestNewConsoleInteractiveHandler(t *testing.T) {
	handler := NewConsoleInteractiveHandler()
	if handler == nil {
		t.Fatal("Expected non-nil handler")
	}
	if handler.timeout != 30*time.Second {
		t.Errorf("Expected default timeout of 30s, got %v", handler.timeout)
	}
}

func TestNewConsoleInteractiveHandlerWithTimeout(t *testing.T) {
	timeout := 60 * time.Second
	handler := NewConsoleInteractiveHandlerWithTimeout(timeout)
	if handler == nil {
		t.Fatal("Expected non-nil handler")
	}
	if handler.timeout != timeout {
		t.Errorf("Expected timeout of %v, got %v", timeout, handler.timeout)
	}
}

func TestConsoleInteractiveHandler_DisplayKeyInfo(t *testing.T) {
	handler := NewConsoleInteractiveHandler()

	now := time.Now()
	keyInfo := &KeyInfo{
		Fingerprint:   "sha256:abcd1234",
		Domain:        "example.com",
		DeveloperName: "Test Developer",
		PinnedAt:      &now,
		LastVerified:  &now,
		IsRevoked:     false,
	}

	result := handler.DisplayKeyInfo(keyInfo)

	if !strings.Contains(result, "sha256:abcd1234") {
		t.Error("Expected fingerprint in output")
	}
	if !strings.Contains(result, "example.com") {
		t.Error("Expected domain in output")
	}
	if !strings.Contains(result, "Test Developer") {
		t.Error("Expected developer name in output")
	}
}

func TestConsoleInteractiveHandler_DisplayKeyInfoRevoked(t *testing.T) {
	handler := NewConsoleInteractiveHandler()

	keyInfo := &KeyInfo{
		Fingerprint: "sha256:abcd1234",
		Domain:      "example.com",
		IsRevoked:   true,
	}

	result := handler.DisplayKeyInfo(keyInfo)

	if !strings.Contains(result, "REVOKED") {
		t.Error("Expected REVOKED status in output")
	}
}

func TestCallbackInteractiveHandler(t *testing.T) {
	var promptCalled bool
	var displayCalled bool
	var warnCalled bool

	promptCallback := func(context *PromptContext) (UserDecision, error) {
		promptCalled = true
		return UserDecisionAccept, nil
	}

	displayCallback := func(keyInfo *KeyInfo) string {
		displayCalled = true
		return "test display"
	}

	warningCallback := func(warning string) {
		warnCalled = true
	}

	handler := NewCallbackInteractiveHandler(promptCallback, displayCallback, warningCallback)

	// Test prompt
	context := &PromptContext{
		PromptType: PromptTypeFirstTimeKey,
		ToolID:     "test-tool",
		Domain:     "example.com",
	}
	decision, err := handler.PromptUser(context)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if decision != UserDecisionAccept {
		t.Errorf("Expected Accept, got %v", decision)
	}
	if !promptCalled {
		t.Error("Expected prompt callback to be called")
	}

	// Test display
	keyInfo := &KeyInfo{Fingerprint: "test"}
	result := handler.DisplayKeyInfo(keyInfo)
	if result != "test display" {
		t.Errorf("Expected 'test display', got %s", result)
	}
	if !displayCalled {
		t.Error("Expected display callback to be called")
	}

	// Test warning
	handler.DisplaySecurityWarning("test warning")
	if !warnCalled {
		t.Error("Expected warning callback to be called")
	}
}

func TestCallbackInteractiveHandler_NoCallbacks(t *testing.T) {
	handler := NewCallbackInteractiveHandler(nil, nil, nil)

	// Test prompt with no callback
	context := &PromptContext{
		PromptType: PromptTypeFirstTimeKey,
		ToolID:     "test-tool",
		Domain:     "example.com",
	}
	decision, err := handler.PromptUser(context)
	if err == nil {
		t.Error("Expected error when no prompt callback configured")
	}
	if decision != UserDecisionReject {
		t.Errorf("Expected Reject on error, got %v", decision)
	}

	// Test display with no callback
	keyInfo := &KeyInfo{Fingerprint: "test"}
	result := handler.DisplayKeyInfo(keyInfo)
	if !strings.Contains(result, "test") {
		t.Error("Expected fallback display to include fingerprint")
	}

	// Test warning with no callback (should not panic)
	handler.DisplaySecurityWarning("test warning")
}

func TestInteractivePinningManager(t *testing.T) {
	mockHandler := &MockInteractiveHandler{
		decision: UserDecisionAccept,
		err:      nil,
	}

	manager := NewInteractivePinningManager(mockHandler)
	if manager == nil {
		t.Fatal("Expected non-nil manager")
	}
	if manager.handler != mockHandler {
		t.Error("Expected handler to be set")
	}
}

func TestInteractivePinningManager_DefaultHandler(t *testing.T) {
	manager := NewInteractivePinningManager(nil)
	if manager == nil {
		t.Fatal("Expected non-nil manager")
	}
	if manager.handler == nil {
		t.Error("Expected default handler to be set")
	}
}

func TestInteractivePinningManager_CreateKeyInfo(t *testing.T) {
	manager := NewInteractivePinningManager(nil)

	// Generate a test key for fingerprint calculation
	keyManager := crypto.NewKeyManager()
	privateKey, err := keyManager.GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	publicKeyPEM, err := keyManager.ExportPublicKeyPEM(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to export public key: %v", err)
	}

	now := time.Now()
	keyInfo, err := manager.CreateKeyInfo(
		publicKeyPEM,
		"example.com",
		"Test Developer",
		&now,
		&now,
		false,
	)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if keyInfo.Domain != "example.com" {
		t.Errorf("Expected domain 'example.com', got %s", keyInfo.Domain)
	}
	if keyInfo.DeveloperName != "Test Developer" {
		t.Errorf("Expected developer 'Test Developer', got %s", keyInfo.DeveloperName)
	}
	if keyInfo.PinnedAt != &now {
		t.Error("Expected pinned time to match")
	}
	if !strings.HasPrefix(keyInfo.Fingerprint, "sha256:") {
		t.Errorf("Expected fingerprint to start with 'sha256:', got %s", keyInfo.Fingerprint)
	}
}

func TestInteractivePinningManager_CreateKeyInfo_InvalidKey(t *testing.T) {
	manager := NewInteractivePinningManager(nil)

	keyInfo, err := manager.CreateKeyInfo(
		"invalid-pem-data",
		"example.com",
		"Test Developer",
		nil,
		nil,
		false,
	)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if keyInfo.Fingerprint != "Invalid key" {
		t.Errorf("Expected 'Invalid key' fingerprint, got %s", keyInfo.Fingerprint)
	}
}

func TestInteractivePinningManager_PromptFirstTimeKey(t *testing.T) {
	mockHandler := &MockInteractiveHandler{
		decision: UserDecisionAccept,
		err:      nil,
	}

	manager := NewInteractivePinningManager(mockHandler)

	// Generate a test key
	keyManager := crypto.NewKeyManager()
	privateKey, err := keyManager.GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	publicKeyPEM, err := keyManager.ExportPublicKeyPEM(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to export public key: %v", err)
	}

	developerInfo := map[string]string{
		"developer_name": "Test Developer",
		"schema_version": "1.1",
	}

	decision, err := manager.PromptFirstTimeKey("test-tool", "example.com", publicKeyPEM, developerInfo)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if decision != UserDecisionAccept {
		t.Errorf("Expected Accept, got %v", decision)
	}
}

func TestInteractivePinningManager_PromptKeyChange(t *testing.T) {
	mockHandler := &MockInteractiveHandler{
		decision: UserDecisionAccept,
		err:      nil,
	}

	manager := NewInteractivePinningManager(mockHandler)

	// Generate test keys
	keyManager := crypto.NewKeyManager()

	currentKey, err := keyManager.GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate current key: %v", err)
	}
	currentKeyPEM, err := keyManager.ExportPublicKeyPEM(&currentKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to export current key: %v", err)
	}

	newKey, err := keyManager.GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate new key: %v", err)
	}
	newKeyPEM, err := keyManager.ExportPublicKeyPEM(&newKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to export new key: %v", err)
	}

	currentKeyInfo := map[string]interface{}{
		"developer_name": "Test Developer",
		"pinned_at":      time.Now().Format(time.RFC3339),
	}

	developerInfo := map[string]string{
		"developer_name": "Test Developer",
		"schema_version": "1.1",
	}

	decision, err := manager.PromptKeyChange("test-tool", "example.com", currentKeyPEM, newKeyPEM, currentKeyInfo, developerInfo)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if decision != UserDecisionAccept {
		t.Errorf("Expected Accept, got %v", decision)
	}
}

func TestInteractivePinningManager_PromptRevokedKey(t *testing.T) {
	mockHandler := &MockInteractiveHandler{
		decision: UserDecisionReject,
		err:      nil,
	}

	manager := NewInteractivePinningManager(mockHandler)

	// Generate a test key
	keyManager := crypto.NewKeyManager()
	privateKey, err := keyManager.GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	publicKeyPEM, err := keyManager.ExportPublicKeyPEM(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to export public key: %v", err)
	}

	keyInfo := map[string]string{
		"developer_name": "Test Developer",
		"pinned_at":      time.Now().Format(time.RFC3339),
	}

	decision, err := manager.PromptRevokedKey("test-tool", "example.com", publicKeyPEM, keyInfo)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if decision != UserDecisionReject {
		t.Errorf("Expected Reject, got %v", decision)
	}
}

func TestInteractivePinningManager_PromptExpiredKey(t *testing.T) {
	mockHandler := &MockInteractiveHandler{
		decision: UserDecisionReject,
		err:      nil,
	}

	manager := NewInteractivePinningManager(mockHandler)

	// Generate a test key
	keyManager := crypto.NewKeyManager()
	privateKey, err := keyManager.GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	publicKeyPEM, err := keyManager.ExportPublicKeyPEM(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to export public key: %v", err)
	}

	keyInfo := map[string]string{
		"developer_name": "Test Developer",
		"pinned_at":      time.Now().Format(time.RFC3339),
	}

	decision, err := manager.PromptExpiredKey("test-tool", "example.com", publicKeyPEM, keyInfo)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if decision != UserDecisionReject {
		t.Errorf("Expected Reject, got %v", decision)
	}
}

// Benchmark tests
func BenchmarkCreateKeyInfo(b *testing.B) {
	manager := NewInteractivePinningManager(nil)

	// Generate a test key
	keyManager := crypto.NewKeyManager()
	privateKey, err := keyManager.GenerateKeypair()
	if err != nil {
		b.Fatalf("Failed to generate test key: %v", err)
	}

	publicKeyPEM, err := keyManager.ExportPublicKeyPEM(&privateKey.PublicKey)
	if err != nil {
		b.Fatalf("Failed to export public key: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := manager.CreateKeyInfo(publicKeyPEM, "example.com", "Test Developer", nil, nil, false)
		if err != nil {
			b.Fatalf("Unexpected error: %v", err)
		}
	}
}

func BenchmarkDisplayKeyInfo(b *testing.B) {
	handler := NewConsoleInteractiveHandler()

	now := time.Now()
	keyInfo := &KeyInfo{
		Fingerprint:   "sha256:abcd1234",
		Domain:        "example.com",
		DeveloperName: "Test Developer",
		PinnedAt:      &now,
		LastVerified:  &now,
		IsRevoked:     false,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = handler.DisplayKeyInfo(keyInfo)
	}
}
