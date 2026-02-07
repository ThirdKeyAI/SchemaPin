// Package pinning provides TOFU key storage and management using BoltDB.
package pinning

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"go.etcd.io/bbolt"

	"github.com/ThirdKeyAi/schemapin/go/pkg/discovery"
	"github.com/ThirdKeyAi/schemapin/go/pkg/interactive"
)

// PinningMode defines the key pinning behavior
type PinningMode string

const (
	PinningModeInteractive PinningMode = "interactive"
	PinningModeAutomatic   PinningMode = "automatic"
	PinningModeStrict      PinningMode = "strict"
)

// PinningPolicy defines domain-specific pinning policies
type PinningPolicy string

const (
	PinningPolicyDefault         PinningPolicy = "default"
	PinningPolicyAlwaysTrust     PinningPolicy = "always_trust"
	PinningPolicyNeverTrust      PinningPolicy = "never_trust"
	PinningPolicyInteractiveOnly PinningPolicy = "interactive_only"
)

// PinnedKeyInfo represents stored key information
type PinnedKeyInfo struct {
	ToolID        string    `json:"tool_id"`
	PublicKeyPEM  string    `json:"public_key_pem"`
	Domain        string    `json:"domain"`
	DeveloperName string    `json:"developer_name,omitempty"`
	PinnedAt      time.Time `json:"pinned_at"`
	LastVerified  time.Time `json:"last_verified,omitempty"`
}

// DomainPolicy represents a domain-specific policy
type DomainPolicy struct {
	Domain    string        `json:"domain"`
	Policy    PinningPolicy `json:"policy"`
	CreatedAt time.Time     `json:"created_at"`
}

// KeyPinning manages TOFU key storage with BoltDB
type KeyPinning struct {
	db                 *bbolt.DB
	dbPath             string
	mode               PinningMode
	interactiveManager *interactive.InteractivePinningManager
	discovery          *discovery.PublicKeyDiscovery
}

var (
	// Bucket names
	pinnedKeysBucket     = []byte("pinned_keys")
	domainPoliciesBucket = []byte("domain_policies")
)

// NewKeyPinning creates a new KeyPinning instance
func NewKeyPinning(dbPath string, mode PinningMode, handler interactive.InteractiveHandler) (*KeyPinning, error) {
	if dbPath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		dbPath = filepath.Join(homeDir, ".schemapin", "pinned_keys.db")
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	// Open BoltDB
	db, err := bbolt.Open(dbPath, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Create buckets
	err = db.Update(func(tx *bbolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(pinnedKeysBucket); err != nil {
			return fmt.Errorf("failed to create pinned_keys bucket: %w", err)
		}
		if _, err := tx.CreateBucketIfNotExists(domainPoliciesBucket); err != nil {
			return fmt.Errorf("failed to create domain_policies bucket: %w", err)
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}

	var interactiveManager *interactive.InteractivePinningManager
	if mode == PinningModeInteractive && handler != nil {
		interactiveManager = interactive.NewInteractivePinningManager(handler)
	}

	return &KeyPinning{
		db:                 db,
		dbPath:             dbPath,
		mode:               mode,
		interactiveManager: interactiveManager,
		discovery:          discovery.NewPublicKeyDiscovery(),
	}, nil
}

// Close closes the database connection
func (k *KeyPinning) Close() error {
	if k.db != nil {
		return k.db.Close()
	}
	return nil
}

// PinKey stores a public key for a tool
func (k *KeyPinning) PinKey(toolID, publicKeyPEM, domain, developerName string) error {
	keyInfo := PinnedKeyInfo{
		ToolID:        toolID,
		PublicKeyPEM:  publicKeyPEM,
		Domain:        domain,
		DeveloperName: developerName,
		PinnedAt:      time.Now().UTC(),
	}

	data, err := json.Marshal(keyInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal key info: %w", err)
	}

	return k.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(pinnedKeysBucket)
		return bucket.Put([]byte(toolID), data)
	})
}

// GetPinnedKey retrieves the pinned public key for a tool
func (k *KeyPinning) GetPinnedKey(toolID string) (string, error) {
	var publicKeyPEM string
	err := k.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(pinnedKeysBucket)
		data := bucket.Get([]byte(toolID))
		if data == nil {
			return nil // Not found
		}

		var keyInfo PinnedKeyInfo
		if err := json.Unmarshal(data, &keyInfo); err != nil {
			return fmt.Errorf("failed to unmarshal key info: %w", err)
		}

		publicKeyPEM = keyInfo.PublicKeyPEM
		return nil
	})

	if err != nil {
		return "", err
	}
	if publicKeyPEM == "" {
		return "", nil // Not found
	}

	return publicKeyPEM, nil
}

// IsKeyPinned checks if a key is pinned for a tool
func (k *KeyPinning) IsKeyPinned(toolID string) bool {
	key, err := k.GetPinnedKey(toolID)
	return err == nil && key != ""
}

// UpdateLastVerified updates the last verification timestamp
func (k *KeyPinning) UpdateLastVerified(toolID string) error {
	return k.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(pinnedKeysBucket)
		data := bucket.Get([]byte(toolID))
		if data == nil {
			return fmt.Errorf("tool not found: %s", toolID)
		}

		var keyInfo PinnedKeyInfo
		if err := json.Unmarshal(data, &keyInfo); err != nil {
			return fmt.Errorf("failed to unmarshal key info: %w", err)
		}

		keyInfo.LastVerified = time.Now().UTC()

		updatedData, err := json.Marshal(keyInfo)
		if err != nil {
			return fmt.Errorf("failed to marshal updated key info: %w", err)
		}

		return bucket.Put([]byte(toolID), updatedData)
	})
}

// SetDomainPolicy sets the pinning policy for a domain
func (k *KeyPinning) SetDomainPolicy(domain string, policy PinningPolicy) error {
	domainPolicy := DomainPolicy{
		Domain:    domain,
		Policy:    policy,
		CreatedAt: time.Now().UTC(),
	}

	data, err := json.Marshal(domainPolicy)
	if err != nil {
		return fmt.Errorf("failed to marshal domain policy: %w", err)
	}

	return k.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(domainPoliciesBucket)
		return bucket.Put([]byte(domain), data)
	})
}

// GetDomainPolicy retrieves the pinning policy for a domain
func (k *KeyPinning) GetDomainPolicy(domain string) PinningPolicy {
	var policy PinningPolicy = PinningPolicyDefault

	k.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(domainPoliciesBucket)
		data := bucket.Get([]byte(domain))
		if data == nil {
			return nil // Use default
		}

		var domainPolicy DomainPolicy
		if err := json.Unmarshal(data, &domainPolicy); err != nil {
			return nil // Use default on error
		}

		policy = domainPolicy.Policy
		return nil
	})

	return policy
}

// GetKeyInfo retrieves complete information about a pinned key
func (k *KeyPinning) GetKeyInfo(toolID string) (*PinnedKeyInfo, error) {
	var keyInfo *PinnedKeyInfo
	err := k.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(pinnedKeysBucket)
		data := bucket.Get([]byte(toolID))
		if data == nil {
			return nil // Not found
		}

		var info PinnedKeyInfo
		if err := json.Unmarshal(data, &info); err != nil {
			return fmt.Errorf("failed to unmarshal key info: %w", err)
		}

		keyInfo = &info
		return nil
	})

	return keyInfo, err
}

// ListPinnedKeys lists all pinned keys with metadata
func (k *KeyPinning) ListPinnedKeys() ([]map[string]interface{}, error) {
	var keys []map[string]interface{}

	err := k.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(pinnedKeysBucket)
		return bucket.ForEach(func(k, v []byte) error {
			var keyInfo PinnedKeyInfo
			if err := json.Unmarshal(v, &keyInfo); err != nil {
				return err
			}

			keyMap := map[string]interface{}{
				"tool_id":        keyInfo.ToolID,
				"domain":         keyInfo.Domain,
				"developer_name": keyInfo.DeveloperName,
				"pinned_at":      keyInfo.PinnedAt.Format(time.RFC3339),
			}

			if !keyInfo.LastVerified.IsZero() {
				keyMap["last_verified"] = keyInfo.LastVerified.Format(time.RFC3339)
			}

			keys = append(keys, keyMap)
			return nil
		})
	})

	return keys, err
}

// RemovePinnedKey removes a pinned key for a tool
func (k *KeyPinning) RemovePinnedKey(toolID string) error {
	return k.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(pinnedKeysBucket)
		return bucket.Delete([]byte(toolID))
	})
}

// ExportPinnedKeys exports all pinned keys to JSON format
func (k *KeyPinning) ExportPinnedKeys() (string, error) {
	var keys []PinnedKeyInfo

	err := k.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(pinnedKeysBucket)
		return bucket.ForEach(func(k, v []byte) error {
			var keyInfo PinnedKeyInfo
			if err := json.Unmarshal(v, &keyInfo); err != nil {
				return err
			}
			keys = append(keys, keyInfo)
			return nil
		})
	})

	if err != nil {
		return "", err
	}

	data, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal keys: %w", err)
	}

	return string(data), nil
}

// ImportPinnedKeys imports pinned keys from JSON format
func (k *KeyPinning) ImportPinnedKeys(jsonData string, overwrite bool) (int, error) {
	var keys []PinnedKeyInfo
	if err := json.Unmarshal([]byte(jsonData), &keys); err != nil {
		return 0, fmt.Errorf("failed to unmarshal JSON data: %w", err)
	}

	imported := 0
	for _, keyInfo := range keys {
		if !overwrite && k.IsKeyPinned(keyInfo.ToolID) {
			continue
		}

		if overwrite {
			k.RemovePinnedKey(keyInfo.ToolID)
		}

		if err := k.PinKey(keyInfo.ToolID, keyInfo.PublicKeyPEM, keyInfo.Domain, keyInfo.DeveloperName); err == nil {
			imported++
		}
	}

	return imported, nil
}

// InteractivePinKey handles interactive key pinning with user prompts
func (k *KeyPinning) InteractivePinKey(toolID, publicKeyPEM, domain, developerName string) (bool, error) {
	return k.interactivePinKeyWithOptions(toolID, publicKeyPEM, domain, developerName, false)
}

// interactivePinKeyWithOptions handles interactive key pinning with force prompt option
func (k *KeyPinning) interactivePinKeyWithOptions(toolID, publicKeyPEM, domain, developerName string, forcePrompt bool) (bool, error) {
	// Check domain policy first
	domainPolicy := k.GetDomainPolicy(domain)

	if domainPolicy == PinningPolicyNeverTrust {
		return false, nil
	} else if domainPolicy == PinningPolicyAlwaysTrust {
		return k.PinKey(toolID, publicKeyPEM, domain, developerName) == nil, nil
	}

	// Check if key is already pinned
	existingKey, err := k.GetPinnedKey(toolID)
	if err != nil {
		return false, fmt.Errorf("failed to check existing key: %w", err)
	}

	if existingKey != "" {
		if existingKey == publicKeyPEM {
			// Same key, just update verification time
			k.UpdateLastVerified(toolID)
			return true, nil
		} else {
			// Different key - handle key change
			return k.handleKeyChange(toolID, domain, existingKey, publicKeyPEM, developerName)
		}
	}

	// First-time key encounter
	return k.handleFirstTimeKey(toolID, domain, publicKeyPEM, developerName, forcePrompt)
}

// handleFirstTimeKey handles first-time key encounter
func (k *KeyPinning) handleFirstTimeKey(toolID, domain, publicKeyPEM, developerName string, forcePrompt bool) (bool, error) {
	// Check if key is revoked
	isNotRevoked, err := k.discovery.ValidateKeyNotRevokedWithTimeout(publicKeyPEM, domain, 10*time.Second)
	if err != nil {
		// If we can't check revocation, proceed with caution
		isNotRevoked = true
	}

	if !isNotRevoked {
		if k.interactiveManager != nil {
			decision, err := k.interactiveManager.PromptRevokedKey(toolID, domain, publicKeyPEM, map[string]string{
				"developer_name": developerName,
			})
			if err != nil {
				return false, err
			}
			return decision == interactive.UserDecisionAccept, nil // Temporary accept for revoked keys
		}
		return false, nil
	}

	// Automatic mode without force prompt
	if k.mode == PinningModeAutomatic && !forcePrompt {
		return k.PinKey(toolID, publicKeyPEM, domain, developerName) == nil, nil
	}

	// Interactive mode or forced prompt
	if k.interactiveManager != nil {
		developerInfo, err := k.discovery.GetDeveloperInfoWithTimeout(domain, 10*time.Second)
		if err != nil {
			// Use provided developer name if discovery fails
			developerInfo = map[string]string{
				"developer_name": developerName,
				"schema_version": "1.0",
			}
		}

		decision, err := k.interactiveManager.PromptFirstTimeKey(toolID, domain, publicKeyPEM, developerInfo)
		if err != nil {
			return false, err
		}

		switch decision {
		case interactive.UserDecisionAccept:
			return k.PinKey(toolID, publicKeyPEM, domain, developerName) == nil, nil
		case interactive.UserDecisionAlwaysTrust:
			k.SetDomainPolicy(domain, PinningPolicyAlwaysTrust)
			return k.PinKey(toolID, publicKeyPEM, domain, developerName) == nil, nil
		case interactive.UserDecisionNeverTrust:
			k.SetDomainPolicy(domain, PinningPolicyNeverTrust)
			return false, nil
		default:
			return false, nil
		}
	}

	return false, nil
}

// handleKeyChange handles key change scenario
func (k *KeyPinning) handleKeyChange(toolID, domain, currentKeyPEM, newKeyPEM, developerName string) (bool, error) {
	// Check if new key is revoked
	isNotRevoked, err := k.discovery.ValidateKeyNotRevokedWithTimeout(newKeyPEM, domain, 10*time.Second)
	if err != nil {
		isNotRevoked = true // Assume not revoked if check fails
	}

	if !isNotRevoked {
		if k.interactiveManager != nil {
			decision, err := k.interactiveManager.PromptRevokedKey(toolID, domain, newKeyPEM, map[string]string{
				"developer_name": developerName,
			})
			if err != nil {
				return false, err
			}
			return decision == interactive.UserDecisionAccept, nil // Temporary accept for revoked keys
		}
		return false, nil
	}

	// In strict mode, always reject key changes
	if k.mode == PinningModeStrict {
		return false, nil
	}

	// Interactive prompt for key change
	if k.interactiveManager != nil {
		currentKeyInfo, _ := k.GetKeyInfo(toolID)
		currentKeyInfoMap := make(map[string]interface{})
		if currentKeyInfo != nil {
			currentKeyInfoMap["tool_id"] = currentKeyInfo.ToolID
			currentKeyInfoMap["domain"] = currentKeyInfo.Domain
			currentKeyInfoMap["developer_name"] = currentKeyInfo.DeveloperName
			currentKeyInfoMap["pinned_at"] = currentKeyInfo.PinnedAt.Format(time.RFC3339)
			if !currentKeyInfo.LastVerified.IsZero() {
				currentKeyInfoMap["last_verified"] = currentKeyInfo.LastVerified.Format(time.RFC3339)
			}
		}

		developerInfo, err := k.discovery.GetDeveloperInfoWithTimeout(domain, 10*time.Second)
		if err != nil {
			developerInfo = map[string]string{
				"developer_name": developerName,
				"schema_version": "1.0",
			}
		}

		decision, err := k.interactiveManager.PromptKeyChange(toolID, domain, currentKeyPEM, newKeyPEM, currentKeyInfoMap, developerInfo)
		if err != nil {
			return false, err
		}

		switch decision {
		case interactive.UserDecisionAccept:
			// Remove old key and pin new one
			_ = k.RemovePinnedKey(toolID)
			return k.PinKey(toolID, newKeyPEM, domain, developerName) == nil, nil
		case interactive.UserDecisionAlwaysTrust:
			_ = k.SetDomainPolicy(domain, PinningPolicyAlwaysTrust)
			_ = k.RemovePinnedKey(toolID)
			return k.PinKey(toolID, newKeyPEM, domain, developerName) == nil, nil
		case interactive.UserDecisionNeverTrust:
			_ = k.SetDomainPolicy(domain, PinningPolicyNeverTrust)
			return false, nil
		default:
			return false, nil
		}
	}

	return false, nil
}

// VerifyWithInteractivePinning verifies and potentially pins a key with interactive prompts
func (k *KeyPinning) VerifyWithInteractivePinning(toolID, domain, publicKeyPEM, developerName string) (bool, error) {
	return k.InteractivePinKey(toolID, publicKeyPEM, domain, developerName)
}
