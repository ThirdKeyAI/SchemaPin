// Package interactive provides user interaction interfaces for SchemaPin key pinning.
package interactive

import (
	"fmt"
	"time"
)

// PromptType defines the type of user prompt
type PromptType string

const (
	PromptTypeFirstTime PromptType = "first_time"
	PromptTypeKeyChange PromptType = "key_change"
	PromptTypeRevoked   PromptType = "revoked"
)

// UserDecision represents the user's decision
type UserDecision string

const (
	UserDecisionAccept UserDecision = "accept"
	UserDecisionReject UserDecision = "reject"
	UserDecisionAlways UserDecision = "always"
	UserDecisionNever  UserDecision = "never"
)

// KeyInfo represents key information for display
type KeyInfo struct {
	Fingerprint   string
	PEMData       string
	Domain        string
	DeveloperName string
	PinnedAt      time.Time
	LastVerified  time.Time
	IsRevoked     bool
}

// PromptContext provides context for interactive prompts
type PromptContext struct {
	PromptType      PromptType
	ToolID          string
	Domain          string
	CurrentKey      *KeyInfo
	NewKey          *KeyInfo
	DeveloperInfo   map[string]string
	SecurityWarning string
}

// InteractiveHandler interface for user interaction
type InteractiveHandler interface {
	PromptUser(context *PromptContext) (UserDecision, error)
	DisplayKeyInfo(keyInfo *KeyInfo) string
	DisplaySecurityWarning(warning string)
}

// ConsoleInteractiveHandler implements console-based interaction
type ConsoleInteractiveHandler struct{}

// NewConsoleInteractiveHandler creates a new console handler
func NewConsoleInteractiveHandler() *ConsoleInteractiveHandler {
	return &ConsoleInteractiveHandler{}
}

// PromptUser prompts the user for a decision via console
func (c *ConsoleInteractiveHandler) PromptUser(context *PromptContext) (UserDecision, error) {
	// TODO: Implement console-based user prompting
	fmt.Printf("Interactive prompt for %s (type: %s)\n", context.ToolID, context.PromptType)
	return UserDecisionAccept, nil
}

// DisplayKeyInfo formats key information for display
func (c *ConsoleInteractiveHandler) DisplayKeyInfo(keyInfo *KeyInfo) string {
	// TODO: Implement formatted key info display
	return fmt.Sprintf("Key: %s (Domain: %s)", keyInfo.Fingerprint, keyInfo.Domain)
}

// DisplaySecurityWarning displays a security warning
func (c *ConsoleInteractiveHandler) DisplaySecurityWarning(warning string) {
	// TODO: Implement formatted security warning display
	fmt.Printf("⚠️  SECURITY WARNING: %s\n", warning)
}

// CallbackInteractiveHandler implements callback-based interaction
type CallbackInteractiveHandler struct {
	promptCallback  func(*PromptContext) (UserDecision, error)
	displayCallback func(*KeyInfo) string
	warningCallback func(string)
}

// NewCallbackInteractiveHandler creates a new callback handler
func NewCallbackInteractiveHandler(
	promptCallback func(*PromptContext) (UserDecision, error),
	displayCallback func(*KeyInfo) string,
	warningCallback func(string),
) *CallbackInteractiveHandler {
	return &CallbackInteractiveHandler{
		promptCallback:  promptCallback,
		displayCallback: displayCallback,
		warningCallback: warningCallback,
	}
}

// PromptUser prompts the user via callback
func (c *CallbackInteractiveHandler) PromptUser(context *PromptContext) (UserDecision, error) {
	if c.promptCallback != nil {
		return c.promptCallback(context)
	}
	return UserDecisionReject, fmt.Errorf("no prompt callback configured")
}

// DisplayKeyInfo formats key information via callback
func (c *CallbackInteractiveHandler) DisplayKeyInfo(keyInfo *KeyInfo) string {
	if c.displayCallback != nil {
		return c.displayCallback(keyInfo)
	}
	return fmt.Sprintf("Key: %s", keyInfo.Fingerprint)
}

// DisplaySecurityWarning displays warning via callback
func (c *CallbackInteractiveHandler) DisplaySecurityWarning(warning string) {
	if c.warningCallback != nil {
		c.warningCallback(warning)
	}
}

// InteractivePinningManager manages interactive key pinning
type InteractivePinningManager struct {
	handler InteractiveHandler
}

// NewInteractivePinningManager creates a new interactive pinning manager
func NewInteractivePinningManager(handler InteractiveHandler) *InteractivePinningManager {
	return &InteractivePinningManager{
		handler: handler,
	}
}

// PromptFirstTimeKey prompts for first-time key pinning
func (i *InteractivePinningManager) PromptFirstTimeKey(toolID, domain, publicKeyPEM string, developerInfo map[string]string) (UserDecision, error) {
	// TODO: Implement first-time key prompting logic
	context := &PromptContext{
		PromptType:    PromptTypeFirstTime,
		ToolID:        toolID,
		Domain:        domain,
		DeveloperInfo: developerInfo,
	}
	return i.handler.PromptUser(context)
}

// PromptKeyChange prompts for key change confirmation
func (i *InteractivePinningManager) PromptKeyChange(toolID, domain, currentKeyPEM, newKeyPEM string, currentKeyInfo map[string]interface{}, developerInfo map[string]string) (UserDecision, error) {
	// TODO: Implement key change prompting logic
	context := &PromptContext{
		PromptType:      PromptTypeKeyChange,
		ToolID:          toolID,
		Domain:          domain,
		DeveloperInfo:   developerInfo,
		SecurityWarning: "Key has changed! This could indicate a security issue.",
	}
	return i.handler.PromptUser(context)
}

// PromptRevokedKey prompts for revoked key handling
func (i *InteractivePinningManager) PromptRevokedKey(toolID, domain, revokedKeyPEM string, keyInfo map[string]string) (UserDecision, error) {
	// TODO: Implement revoked key prompting logic
	context := &PromptContext{
		PromptType:      PromptTypeRevoked,
		ToolID:          toolID,
		Domain:          domain,
		SecurityWarning: "This key has been revoked by the developer!",
	}
	return i.handler.PromptUser(context)
}
