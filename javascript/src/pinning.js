/**
 * Key pinning storage and management for Trust-On-First-Use (TOFU).
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { homedir } from 'os';
import {
    InteractivePinningManager,
    UserDecision,
    PromptType,
    InteractiveHandler
} from './interactive.js';

/**
 * Pinning operation modes.
 */
export const PinningMode = {
    AUTOMATIC: 'automatic',
    INTERACTIVE: 'interactive',
    STRICT: 'strict'
};

/**
 * Per-domain pinning policies.
 */
export const PinningPolicy = {
    DEFAULT: 'default',
    ALWAYS_TRUST: 'always_trust',
    NEVER_TRUST: 'never_trust',
    INTERACTIVE_ONLY: 'interactive_only'
};

/**
 * Manages key pinning storage using JSON file.
 */
export class KeyPinning {
    /**
     * Initialize key pinning storage.
     *
     * @param {string|null} dbPath - Path to JSON storage file. If null, uses default location.
     * @param {string} mode - Pinning operation mode (automatic, interactive, strict)
     * @param {InteractiveHandler|null} interactiveHandler - Handler for interactive prompts
     */
    constructor(dbPath = null, mode = PinningMode.AUTOMATIC, interactiveHandler = null) {
        if (dbPath === null) {
            const homeDir = homedir();
            dbPath = join(homeDir, '.schemapin', 'pinned_keys.json');
        }
        
        this.dbPath = dbPath;
        this.mode = mode;
        this.interactiveManager = mode === PinningMode.INTERACTIVE ?
            new InteractivePinningManager(interactiveHandler) : null;
        this._ensureDbDirectory();
        this._initDatabase();
    }

    /**
     * Ensure database directory exists.
     * @private
     */
    _ensureDbDirectory() {
        const dir = dirname(this.dbPath);
        if (!existsSync(dir)) {
            mkdirSync(dir, { recursive: true });
        }
    }

    /**
     * Initialize database file.
     * @private
     */
    _initDatabase() {
        if (!existsSync(this.dbPath)) {
            this._saveData({
                pinned_keys: {},
                domain_policies: {}
            });
        } else {
            // Migrate old format if needed
            const data = this._loadData();
            if (!data.pinned_keys && !data.domain_policies) {
                // Old format - migrate
                this._saveData({
                    pinned_keys: data,
                    domain_policies: {}
                });
            }
        }
    }

    /**
     * Load data from JSON file.
     * @private
     * @returns {Object} Pinned keys data
     */
    _loadData() {
        try {
            const data = readFileSync(this.dbPath, 'utf8');
            const parsed = JSON.parse(data);
            
            // Handle both old and new format
            if (parsed.pinned_keys !== undefined) {
                return parsed;
            } else {
                // Old format
                return {
                    pinned_keys: parsed,
                    domain_policies: {}
                };
            }
        } catch (error) {
            return {
                pinned_keys: {},
                domain_policies: {}
            };
        }
    }

    /**
     * Save data to JSON file.
     * @private
     * @param {Object} data - Data to save
     */
    _saveData(data) {
        writeFileSync(this.dbPath, JSON.stringify(data, null, 2), 'utf8');
    }

    /**
     * Pin a public key for a tool.
     *
     * @param {string} toolId - Unique tool identifier
     * @param {string} publicKeyPem - PEM-encoded public key
     * @param {string} domain - Tool provider domain
     * @param {string|null} developerName - Optional developer name
     * @returns {boolean} True if key was pinned successfully, false if already exists
     */
    pinKey(toolId, publicKeyPem, domain, developerName = null) {
        const data = this._loadData();
        
        if (toolId in data.pinned_keys) {
            return false; // Key already exists
        }
        
        data.pinned_keys[toolId] = {
            public_key_pem: publicKeyPem,
            domain: domain,
            developer_name: developerName,
            pinned_at: new Date().toISOString(),
            last_verified: null
        };
        
        this._saveData(data);
        return true;
    }

    /**
     * Get pinned public key for tool.
     *
     * @param {string} toolId - Tool identifier
     * @returns {string|null} PEM-encoded public key if pinned, null otherwise
     */
    getPinnedKey(toolId) {
        const data = this._loadData();
        const keyInfo = data.pinned_keys[toolId];
        return keyInfo ? keyInfo.public_key_pem : null;
    }

    /**
     * Check if key is pinned for tool.
     *
     * @param {string} toolId - Tool identifier
     * @returns {boolean} True if key is pinned, false otherwise
     */
    isKeyPinned(toolId) {
        return this.getPinnedKey(toolId) !== null;
    }

    /**
     * Update last verification timestamp for tool.
     *
     * @param {string} toolId - Tool identifier
     * @returns {boolean} True if updated successfully, false if tool not found
     */
    updateLastVerified(toolId) {
        const data = this._loadData();
        
        if (!(toolId in data.pinned_keys)) {
            return false;
        }
        
        data.pinned_keys[toolId].last_verified = new Date().toISOString();
        this._saveData(data);
        return true;
    }

    /**
     * List all pinned keys with metadata.
     *
     * @returns {Array} Array of objects containing key information
     */
    listPinnedKeys() {
        const data = this._loadData();
        return Object.entries(data.pinned_keys)
            .map(([toolId, keyInfo]) => ({
                tool_id: toolId,
                domain: keyInfo.domain,
                developer_name: keyInfo.developer_name,
                pinned_at: keyInfo.pinned_at,
                last_verified: keyInfo.last_verified
            }))
            .sort((a, b) => new Date(b.pinned_at) - new Date(a.pinned_at));
    }

    /**
     * Remove pinned key for tool.
     *
     * @param {string} toolId - Tool identifier
     * @returns {boolean} True if removed successfully, false if not found
     */
    removePinnedKey(toolId) {
        const data = this._loadData();
        
        if (!(toolId in data.pinned_keys)) {
            return false;
        }
        
        delete data.pinned_keys[toolId];
        this._saveData(data);
        return true;
    }

    /**
     * Get complete information about pinned key.
     *
     * @param {string} toolId - Tool identifier
     * @returns {Object|null} Object with key information if found, null otherwise
     */
    getKeyInfo(toolId) {
        const data = this._loadData();
        const keyInfo = data.pinned_keys[toolId];
        
        if (!keyInfo) {
            return null;
        }
        
        return {
            tool_id: toolId,
            public_key_pem: keyInfo.public_key_pem,
            domain: keyInfo.domain,
            developer_name: keyInfo.developer_name,
            pinned_at: keyInfo.pinned_at,
            last_verified: keyInfo.last_verified
        };
    }

    /**
     * Export all pinned keys to JSON format.
     * 
     * @returns {string} JSON string containing all pinned keys
     */
    exportPinnedKeys() {
        const keys = this.listPinnedKeys();
        // Add public key data for export
        keys.forEach(keyInfo => {
            keyInfo.public_key_pem = this.getPinnedKey(keyInfo.tool_id);
        });
        
        return JSON.stringify(keys, null, 2);
    }

    /**
     * Import pinned keys from JSON format.
     * 
     * @param {string} jsonData - JSON string containing key data
     * @param {boolean} overwrite - Whether to overwrite existing keys
     * @returns {number} Number of keys imported
     */
    importPinnedKeys(jsonData, overwrite = false) {
        try {
            const keys = JSON.parse(jsonData);
            let imported = 0;
            
            for (const keyInfo of keys) {
                if (overwrite && this.isKeyPinned(keyInfo.tool_id)) {
                    this.removePinnedKey(keyInfo.tool_id);
                }
                
                if (this.pinKey(
                    keyInfo.tool_id,
                    keyInfo.public_key_pem,
                    keyInfo.domain,
                    keyInfo.developer_name
                )) {
                    imported++;
                }
            }
            
            return imported;
        } catch (error) {
            return 0;
        }
    }

    /**
     * Set pinning policy for a domain.
     *
     * @param {string} domain - Domain to set policy for
     * @param {string} policy - Pinning policy to apply
     * @returns {boolean} True if policy was set successfully
     */
    setDomainPolicy(domain, policy) {
        try {
            const data = this._loadData();
            data.domain_policies[domain] = {
                policy: policy,
                created_at: new Date().toISOString()
            };
            this._saveData(data);
            return true;
        } catch (error) {
            return false;
        }
    }

    /**
     * Get pinning policy for a domain.
     *
     * @param {string} domain - Domain to get policy for
     * @returns {string} Pinning policy for domain, defaults to DEFAULT
     */
    getDomainPolicy(domain) {
        const data = this._loadData();
        const policyInfo = data.domain_policies[domain];
        return policyInfo ? policyInfo.policy : PinningPolicy.DEFAULT;
    }

    /**
     * Pin a key with interactive user confirmation.
     *
     * @param {string} toolId - Unique tool identifier
     * @param {string} publicKeyPem - PEM-encoded public key
     * @param {string} domain - Tool provider domain
     * @param {string|null} developerName - Optional developer name
     * @param {boolean} forcePrompt - Force interactive prompt even in automatic mode
     * @returns {Promise<boolean>} True if key was pinned, false if rejected or error
     */
    async interactivePinKey(toolId, publicKeyPem, domain, developerName = null, forcePrompt = false) {
        // Check domain policy first
        const domainPolicy = this.getDomainPolicy(domain);
        
        if (domainPolicy === PinningPolicy.NEVER_TRUST) {
            return false;
        } else if (domainPolicy === PinningPolicy.ALWAYS_TRUST) {
            return this.pinKey(toolId, publicKeyPem, domain, developerName);
        }
        
        // Check if key is already pinned
        const existingKey = this.getPinnedKey(toolId);
        if (existingKey) {
            if (existingKey === publicKeyPem) {
                // Same key, just update verification time
                this.updateLastVerified(toolId);
                return true;
            } else {
                // Different key - handle key change
                return await this._handleKeyChange(toolId, domain, existingKey,
                                                 publicKeyPem, developerName);
            }
        }
        
        // First-time key encounter
        return await this._handleFirstTimeKey(toolId, domain, publicKeyPem,
                                            developerName, forcePrompt);
    }

    /**
     * Handle first-time key encounter.
     * @private
     */
    async _handleFirstTimeKey(toolId, domain, publicKeyPem, developerName, forcePrompt) {
        // Note: In a full implementation, you'd check revocation here
        // For now, we'll assume the key is not revoked
        
        // Automatic mode without force prompt
        if (this.mode === PinningMode.AUTOMATIC && !forcePrompt) {
            return this.pinKey(toolId, publicKeyPem, domain, developerName);
        }
        
        // Interactive mode or forced prompt
        if (this.interactiveManager) {
            // Note: In a full implementation, you'd fetch developer info here
            const developerInfo = { developer_name: developerName };
            
            const decision = await this.interactiveManager.promptFirstTimeKey(
                toolId, domain, publicKeyPem, developerInfo
            );
            
            if (decision === UserDecision.ACCEPT) {
                return this.pinKey(toolId, publicKeyPem, domain, developerName);
            } else if (decision === UserDecision.ALWAYS_TRUST) {
                this.setDomainPolicy(domain, PinningPolicy.ALWAYS_TRUST);
                return this.pinKey(toolId, publicKeyPem, domain, developerName);
            } else if (decision === UserDecision.NEVER_TRUST) {
                this.setDomainPolicy(domain, PinningPolicy.NEVER_TRUST);
                return false;
            } else if (decision === UserDecision.TEMPORARY_ACCEPT) {
                // Don't pin, but allow this verification
                return true;
            }
        }
        
        return false;
    }

    /**
     * Handle key change scenario.
     * @private
     */
    async _handleKeyChange(toolId, domain, currentKeyPem, newKeyPem, developerName) {
        // Note: In a full implementation, you'd check revocation here
        
        // In strict mode, always reject key changes
        if (this.mode === PinningMode.STRICT) {
            return false;
        }
        
        // Interactive prompt for key change
        if (this.interactiveManager) {
            const currentKeyInfo = this.getKeyInfo(toolId);
            // Note: In a full implementation, you'd fetch developer info here
            const developerInfo = { developer_name: developerName };
            
            const decision = await this.interactiveManager.promptKeyChange(
                toolId, domain, currentKeyPem, newKeyPem,
                currentKeyInfo, developerInfo
            );
            
            if (decision === UserDecision.ACCEPT) {
                // Remove old key and pin new one
                this.removePinnedKey(toolId);
                return this.pinKey(toolId, newKeyPem, domain, developerName);
            } else if (decision === UserDecision.ALWAYS_TRUST) {
                this.setDomainPolicy(domain, PinningPolicy.ALWAYS_TRUST);
                this.removePinnedKey(toolId);
                return this.pinKey(toolId, newKeyPem, domain, developerName);
            } else if (decision === UserDecision.NEVER_TRUST) {
                this.setDomainPolicy(domain, PinningPolicy.NEVER_TRUST);
                return false;
            } else if (decision === UserDecision.TEMPORARY_ACCEPT) {
                // Don't update pinned key, but allow this verification
                return true;
            }
        }
        
        return false;
    }

    /**
     * Verify and potentially pin a key with interactive prompts.
     *
     * @param {string} toolId - Tool identifier
     * @param {string} domain - Tool provider domain
     * @param {string} publicKeyPem - PEM-encoded public key to verify
     * @param {string|null} developerName - Optional developer name
     * @returns {Promise<boolean>} True if key is verified/pinned and can be used, false otherwise
     */
    async verifyWithInteractivePinning(toolId, domain, publicKeyPem, developerName = null) {
        return await this.interactivePinKey(toolId, publicKeyPem, domain, developerName);
    }
}