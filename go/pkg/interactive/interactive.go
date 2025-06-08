// Package interactive provides user interaction interfaces for SchemaPin key pinning.
package interactive

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ThirdKeyAi/schemapin/go/pkg/crypto"
)

// PromptType defines the type of user prompt
type PromptType string

const (
	PromptTypeFirstTimeKey PromptType = "first_time_key"
	PromptTypeKeyChange    PromptType = "key_change"
	PromptTypeRevokedKey   PromptType = "revoked_key"
	PromptTypeExpiredKey   PromptType = "expired_key"
)

// UserDecision represents the user's decision
type UserDecision string

const (
	UserDecisionAccept          UserDecision = "accept"
	UserDecisionReject          UserDecision = "reject"
	UserDecisionAlwaysTrust     UserDecision = "always_trust"
	UserDecisionNeverTrust      UserDecision = "never_trust"
	UserDecisionTemporaryAccept UserDecision = "temporary_accept"
)

// KeyInfo represents key information for display
type KeyInfo struct {
	Fingerprint   string
	PEMData       string
	Domain        string
	DeveloperName string
	PinnedAt      *time.Time
	LastVerified  *time.Time
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
type ConsoleInteractiveHandler struct {
	reader  *bufio.Reader
	timeout time.Duration
}

// NewConsoleInteractiveHandler creates a new console handler
func NewConsoleInteractiveHandler() *ConsoleInteractiveHandler {
	return &ConsoleInteractiveHandler{
		reader:  bufio.NewReader(os.Stdin),
		timeout: 30 * time.Second, // Default 30 second timeout
	}
}

// NewConsoleInteractiveHandlerWithTimeout creates a new console handler with custom timeout
func NewConsoleInteractiveHandlerWithTimeout(timeout time.Duration) *ConsoleInteractiveHandler {
	return &ConsoleInteractiveHandler{
		reader:  bufio.NewReader(os.Stdin),
		timeout: timeout,
	}
}

// PromptUser prompts the user for a decision via console
func (c *ConsoleInteractiveHandler) PromptUser(context *PromptContext) (UserDecision, error) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("SCHEMAPIN SECURITY PROMPT")
	fmt.Println(strings.Repeat("=", 60))

	switch context.PromptType {
	case PromptTypeFirstTimeKey:
		c.displayFirstTimePrompt(context)
	case PromptTypeKeyChange:
		c.displayKeyChangePrompt(context)
	case PromptTypeRevokedKey:
		c.displayRevokedKeyPrompt(context)
	case PromptTypeExpiredKey:
		c.displayExpiredKeyPrompt(context)
	}

	return c.getUserChoice(context.PromptType)
}

// DisplayKeyInfo formats key information for console display
func (c *ConsoleInteractiveHandler) DisplayKeyInfo(keyInfo *KeyInfo) string {
	var lines []string
	lines = append(lines, fmt.Sprintf("Fingerprint: %s", keyInfo.Fingerprint))
	lines = append(lines, fmt.Sprintf("Domain: %s", keyInfo.Domain))

	if keyInfo.DeveloperName != "" {
		lines = append(lines, fmt.Sprintf("Developer: %s", keyInfo.DeveloperName))
	}

	if keyInfo.PinnedAt != nil {
		lines = append(lines, fmt.Sprintf("Pinned: %s", keyInfo.PinnedAt.Format(time.RFC3339)))
	}

	if keyInfo.LastVerified != nil {
		lines = append(lines, fmt.Sprintf("Last Verified: %s", keyInfo.LastVerified.Format(time.RFC3339)))
	}

	if keyInfo.IsRevoked {
		lines = append(lines, "⚠️  STATUS: REVOKED")
	}

	return strings.Join(lines, "\n")
}

// DisplaySecurityWarning displays a security warning
func (c *ConsoleInteractiveHandler) DisplaySecurityWarning(warning string) {
	fmt.Printf("\n⚠️  SECURITY WARNING: %s\n", warning)
}

func (c *ConsoleInteractiveHandler) displayFirstTimePrompt(context *PromptContext) {
	fmt.Printf("\nFirst-time key encounter for tool: %s\n", context.ToolID)
	fmt.Printf("Domain: %s\n", context.Domain)

	if context.DeveloperInfo != nil {
		if devName, ok := context.DeveloperInfo["developer_name"]; ok {
			fmt.Printf("Developer: %s\n", devName)
		}
	}

	if context.NewKey != nil {
		fmt.Println("\nNew Key Information:")
		fmt.Println(c.DisplayKeyInfo(context.NewKey))
	}

	fmt.Println("\nThis is the first time you're encountering this tool.")
	fmt.Println("Do you want to pin this key for future verification?")
}

func (c *ConsoleInteractiveHandler) displayKeyChangePrompt(context *PromptContext) {
	fmt.Printf("\n⚠️  KEY CHANGE DETECTED for tool: %s\n", context.ToolID)
	fmt.Printf("Domain: %s\n", context.Domain)

	if context.CurrentKey != nil {
		fmt.Println("\nCurrently Pinned Key:")
		fmt.Println(c.DisplayKeyInfo(context.CurrentKey))
	}

	if context.NewKey != nil {
		fmt.Println("\nNew Key Being Offered:")
		fmt.Println(c.DisplayKeyInfo(context.NewKey))
	}

	fmt.Println("\n⚠️  The tool is using a different key than previously pinned!")
	fmt.Println("This could indicate a legitimate key rotation or a security compromise.")
}

func (c *ConsoleInteractiveHandler) displayRevokedKeyPrompt(context *PromptContext) {
	fmt.Printf("\n🚨 REVOKED KEY DETECTED for tool: %s\n", context.ToolID)
	fmt.Printf("Domain: %s\n", context.Domain)

	if context.CurrentKey != nil {
		fmt.Println("\nRevoked Key Information:")
		fmt.Println(c.DisplayKeyInfo(context.CurrentKey))
	}

	fmt.Println("\n🚨 This key has been marked as revoked by the developer!")
	fmt.Println("Using this tool is NOT RECOMMENDED.")

	if context.SecurityWarning != "" {
		c.DisplaySecurityWarning(context.SecurityWarning)
	}
}

func (c *ConsoleInteractiveHandler) displayExpiredKeyPrompt(context *PromptContext) {
	fmt.Printf("\n⚠️  EXPIRED KEY DETECTED for tool: %s\n", context.ToolID)
	fmt.Printf("Domain: %s\n", context.Domain)

	if context.CurrentKey != nil {
		fmt.Println("\nExpired Key Information:")
		fmt.Println(c.DisplayKeyInfo(context.CurrentKey))
	}

	fmt.Println("\n⚠️  This key has expired and should be updated.")
}

func (c *ConsoleInteractiveHandler) getUserChoice(promptType PromptType) (UserDecision, error) {
	var choices map[string]UserDecision
	var prompt string
	var defaultChoice UserDecision

	if promptType == PromptTypeRevokedKey {
		choices = map[string]UserDecision{
			"r": UserDecisionReject,
			"n": UserDecisionNeverTrust,
		}
		prompt = "\nChoices:\n  r) Reject (recommended)\n  n) Never trust this domain\nChoice [r]: "
		defaultChoice = UserDecisionReject
	} else {
		choices = map[string]UserDecision{
			"a": UserDecisionAccept,
			"r": UserDecisionReject,
			"t": UserDecisionAlwaysTrust,
			"n": UserDecisionNeverTrust,
			"o": UserDecisionTemporaryAccept,
		}
		prompt = "\nChoices:\n" +
			"  a) Accept and pin this key\n" +
			"  r) Reject this key\n" +
			"  t) Always trust this domain\n" +
			"  n) Never trust this domain\n" +
			"  o) Accept once (temporary)\n" +
			"Choice [r]: "
		defaultChoice = UserDecisionReject
	}

	// Create a channel to handle timeout
	resultChan := make(chan UserDecision, 1)
	errorChan := make(chan error, 1)

	go func() {
		for {
			fmt.Print(prompt)
			input, err := c.reader.ReadString('\n')
			if err != nil {
				errorChan <- err
				return
			}

			choice := strings.ToLower(strings.TrimSpace(input))
			if choice == "" {
				resultChan <- defaultChoice
				return
			}

			if decision, ok := choices[choice]; ok {
				resultChan <- decision
				return
			}

			fmt.Println("Invalid choice. Please try again.")
		}
	}()

	// Handle timeout
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	select {
	case decision := <-resultChan:
		return decision, nil
	case err := <-errorChan:
		return UserDecisionReject, err
	case <-ctx.Done():
		fmt.Println("\nTimeout reached. Defaulting to reject.")
		return UserDecisionReject, nil
	}
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

	infoParts := []string{
		fmt.Sprintf("Fingerprint: %s", keyInfo.Fingerprint),
		fmt.Sprintf("Domain: %s", keyInfo.Domain),
	}

	if keyInfo.DeveloperName != "" {
		infoParts = append(infoParts, fmt.Sprintf("Developer: %s", keyInfo.DeveloperName))
	}

	if keyInfo.IsRevoked {
		infoParts = append(infoParts, "STATUS: REVOKED")
	}

	return strings.Join(infoParts, " | ")
}

// DisplaySecurityWarning displays warning via callback
func (c *CallbackInteractiveHandler) DisplaySecurityWarning(warning string) {
	if c.warningCallback != nil {
		c.warningCallback(fmt.Sprintf("SECURITY WARNING: %s", warning))
	}
}

// InteractivePinningManager manages interactive key pinning
type InteractivePinningManager struct {
	handler    InteractiveHandler
	keyManager *crypto.KeyManager
}

// NewInteractivePinningManager creates a new interactive pinning manager
func NewInteractivePinningManager(handler InteractiveHandler) *InteractivePinningManager {
	if handler == nil {
		handler = NewConsoleInteractiveHandler()
	}
	return &InteractivePinningManager{
		handler:    handler,
		keyManager: crypto.NewKeyManager(),
	}
}

// CreateKeyInfo creates KeyInfo object from public key data
func (i *InteractivePinningManager) CreateKeyInfo(publicKeyPEM, domain string, developerName string, pinnedAt, lastVerified *time.Time, isRevoked bool) (*KeyInfo, error) {
	fingerprint, err := i.keyManager.CalculateKeyFingerprintFromPEM(publicKeyPEM)
	if err != nil {
		fingerprint = "Invalid key"
	}

	return &KeyInfo{
		Fingerprint:   fingerprint,
		PEMData:       publicKeyPEM,
		Domain:        domain,
		DeveloperName: developerName,
		PinnedAt:      pinnedAt,
		LastVerified:  lastVerified,
		IsRevoked:     isRevoked,
	}, nil
}

// PromptFirstTimeKey prompts for first-time key pinning
func (i *InteractivePinningManager) PromptFirstTimeKey(toolID, domain, publicKeyPEM string, developerInfo map[string]string) (UserDecision, error) {
	newKey, err := i.CreateKeyInfo(publicKeyPEM, domain, "", nil, nil, false)
	if err != nil {
		return UserDecisionReject, err
	}

	if developerInfo != nil {
		if devName, ok := developerInfo["developer_name"]; ok {
			newKey.DeveloperName = devName
		}
	}

	context := &PromptContext{
		PromptType:    PromptTypeFirstTimeKey,
		ToolID:        toolID,
		Domain:        domain,
		NewKey:        newKey,
		DeveloperInfo: developerInfo,
	}

	return i.handler.PromptUser(context)
}

// PromptKeyChange prompts for key change confirmation
func (i *InteractivePinningManager) PromptKeyChange(toolID, domain, currentKeyPEM, newKeyPEM string, currentKeyInfo map[string]interface{}, developerInfo map[string]string) (UserDecision, error) {
	// Create current key info
	var pinnedAt, lastVerified *time.Time
	var currentDeveloperName string

	if currentKeyInfo != nil {
		if devName, ok := currentKeyInfo["developer_name"].(string); ok {
			currentDeveloperName = devName
		}
		if pinnedAtStr, ok := currentKeyInfo["pinned_at"].(string); ok {
			if t, err := time.Parse(time.RFC3339, pinnedAtStr); err == nil {
				pinnedAt = &t
			}
		}
		if lastVerifiedStr, ok := currentKeyInfo["last_verified"].(string); ok {
			if t, err := time.Parse(time.RFC3339, lastVerifiedStr); err == nil {
				lastVerified = &t
			}
		}
	}

	currentKey, err := i.CreateKeyInfo(currentKeyPEM, domain, currentDeveloperName, pinnedAt, lastVerified, false)
	if err != nil {
		return UserDecisionReject, err
	}

	// Create new key info
	var newDeveloperName string
	if developerInfo != nil {
		if devName, ok := developerInfo["developer_name"]; ok {
			newDeveloperName = devName
		}
	}

	newKey, err := i.CreateKeyInfo(newKeyPEM, domain, newDeveloperName, nil, nil, false)
	if err != nil {
		return UserDecisionReject, err
	}

	context := &PromptContext{
		PromptType:      PromptTypeKeyChange,
		ToolID:          toolID,
		Domain:          domain,
		CurrentKey:      currentKey,
		NewKey:          newKey,
		DeveloperInfo:   developerInfo,
		SecurityWarning: "Key has changed! This could indicate a security issue.",
	}

	return i.handler.PromptUser(context)
}

// PromptRevokedKey prompts for revoked key handling
func (i *InteractivePinningManager) PromptRevokedKey(toolID, domain, revokedKeyPEM string, keyInfo map[string]string) (UserDecision, error) {
	var developerName string
	var pinnedAt, lastVerified *time.Time

	if keyInfo != nil {
		if devName, ok := keyInfo["developer_name"]; ok {
			developerName = devName
		}
		if pinnedAtStr, ok := keyInfo["pinned_at"]; ok {
			if t, err := time.Parse(time.RFC3339, pinnedAtStr); err == nil {
				pinnedAt = &t
			}
		}
		if lastVerifiedStr, ok := keyInfo["last_verified"]; ok {
			if t, err := time.Parse(time.RFC3339, lastVerifiedStr); err == nil {
				lastVerified = &t
			}
		}
	}

	revokedKey, err := i.CreateKeyInfo(revokedKeyPEM, domain, developerName, pinnedAt, lastVerified, true)
	if err != nil {
		return UserDecisionReject, err
	}

	context := &PromptContext{
		PromptType:      PromptTypeRevokedKey,
		ToolID:          toolID,
		Domain:          domain,
		CurrentKey:      revokedKey,
		SecurityWarning: "This key has been revoked by the developer. Do not use this tool.",
	}

	return i.handler.PromptUser(context)
}

// PromptExpiredKey prompts for expired key handling
func (i *InteractivePinningManager) PromptExpiredKey(toolID, domain, expiredKeyPEM string, keyInfo map[string]string) (UserDecision, error) {
	var developerName string
	var pinnedAt, lastVerified *time.Time

	if keyInfo != nil {
		if devName, ok := keyInfo["developer_name"]; ok {
			developerName = devName
		}
		if pinnedAtStr, ok := keyInfo["pinned_at"]; ok {
			if t, err := time.Parse(time.RFC3339, pinnedAtStr); err == nil {
				pinnedAt = &t
			}
		}
		if lastVerifiedStr, ok := keyInfo["last_verified"]; ok {
			if t, err := time.Parse(time.RFC3339, lastVerifiedStr); err == nil {
				lastVerified = &t
			}
		}
	}

	expiredKey, err := i.CreateKeyInfo(expiredKeyPEM, domain, developerName, pinnedAt, lastVerified, false)
	if err != nil {
		return UserDecisionReject, err
	}

	context := &PromptContext{
		PromptType:      PromptTypeExpiredKey,
		ToolID:          toolID,
		Domain:          domain,
		CurrentKey:      expiredKey,
		SecurityWarning: "This key has expired and should be updated.",
	}

	return i.handler.PromptUser(context)
}
