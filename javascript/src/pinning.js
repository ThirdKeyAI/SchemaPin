/**
 * Key pinning storage and management for Trust-On-First-Use (TOFU).
 *
 * @deprecated `KeyPinning` is the legacy PEM-by-tool store used by
 * `SchemaVerificationWorkflow`. New code should use `KeyPinStore`
 * (fingerprint pins keyed by `tool_id@domain`) with `verifySchemaOffline`;
 * this class is retained as a persistence backend for existing deployments.
 *
 * Pins are keyed by `toolId@domain`. A pin made for one domain is never
 * returned for another, so a key pinned for `evil.com` cannot satisfy a
 * verification for `good.com` that happens to reuse the same tool id. The
 * store file is written atomically with mode 0600 and a corrupt file is a
 * hard error rather than a silent reset to "first use".
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync, chmodSync } from 'fs';
import { join, dirname } from 'path';
import { homedir } from 'os';
import {
    InteractivePinningManager,
    UserDecision,
    PromptType,
    InteractiveHandler
} from './interactive.js';
import { PublicKeyDiscovery } from './discovery.js';

/**
 * Thrown when the pin store file cannot be read or parsed. Callers must not
 * treat this as "nothing pinned".
 */
export class PinStoreCorruptError extends Error {
    constructor(message) {
        super(message);
        this.name = 'PinStoreCorruptError';
    }
}

function compositeKey(toolId, domain) {
    return `${toolId}@${domain}`;
}

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
     * @param {{ revocationChecker?: (publicKeyPem: string, domain: string) => Promise<boolean> }} [options]
     *   `revocationChecker` replaces the discovery-backed, fail-closed
     *   revocation check used by the interactive flows (for custom resolvers
     *   or offline bundles).
     * @throws {PinStoreCorruptError} if an existing store file is unreadable or malformed
     */
    constructor(dbPath = null, mode = PinningMode.AUTOMATIC, interactiveHandler = null, options = {}) {
        if (dbPath === null) {
            const homeDir = homedir();
            dbPath = join(homeDir, '.schemapin', 'pinned_keys.json');
        }

        this.dbPath = dbPath;
        this.mode = mode;
        this.interactiveManager = mode === PinningMode.INTERACTIVE ?
            new InteractivePinningManager(interactiveHandler) : null;
        this._revocationChecker = options.revocationChecker
            ?? ((publicKeyPem, domain) => PublicKeyDiscovery.validateKeyNotRevoked(publicKeyPem, domain));
        this._ensureDbDirectory();
        this._initDatabase();
    }

    /**
     * Ensure database directory exists (owner-only).
     * @private
     */
    _ensureDbDirectory() {
        const dir = dirname(this.dbPath);
        if (!existsSync(dir)) {
            mkdirSync(dir, { recursive: true, mode: 0o700 });
        }
    }

    /**
     * Initialize database file, migrating older layouts in place.
     * @private
     */
    _initDatabase() {
        if (!existsSync(this.dbPath)) {
            this._saveData({
                pinned_keys: {},
                domain_policies: {}
            });
            return;
        }
        const data = this._loadData();
        if (data.migrated) {
            delete data.migrated;
            this._saveData(data);
        }
    }

    /**
     * Load data from the JSON file. Unreadable or malformed stores throw:
     * silently starting over would turn every pin into "first use".
     * @private
     * @returns {Object} Pinned keys data
     */
    _loadData() {
        let parsed;
        try {
            parsed = JSON.parse(readFileSync(this.dbPath, 'utf8'));
        } catch (error) {
            throw new PinStoreCorruptError(`pin store ${this.dbPath} is unreadable or malformed: ${error.message}`);
        }
        if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
            throw new PinStoreCorruptError(`pin store ${this.dbPath} is malformed`);
        }
        let data = parsed;
        if (parsed.pinned_keys === undefined) {
            // Oldest layout: the whole file was the pinned_keys map.
            data = { pinned_keys: parsed, domain_policies: {}, migrated: true };
        }
        if (data.pinned_keys === null || typeof data.pinned_keys !== 'object') {
            throw new PinStoreCorruptError(`pin store ${this.dbPath} is malformed`);
        }
        if (!data.domain_policies || typeof data.domain_policies !== 'object') {
            data.domain_policies = {};
        }
        // Migrate entries keyed by bare tool id to toolId@domain.
        for (const [key, info] of Object.entries(data.pinned_keys)) {
            if (!key.includes('@') && info && typeof info.domain === 'string') {
                delete data.pinned_keys[key];
                data.pinned_keys[compositeKey(key, info.domain)] = info;
                data.migrated = true;
            }
        }
        return data;
    }

    /**
     * Save data atomically (temp file + rename) with mode 0600.
     * @private
     * @param {Object} data - Data to save
     */
    _saveData(data) {
        const { migrated: _migrated, ...toWrite } = data;
        const tmp = `${this.dbPath}.${process.pid}.tmp`;
        writeFileSync(tmp, JSON.stringify(toWrite, null, 2), { encoding: 'utf8', mode: 0o600 });
        try {
            chmodSync(tmp, 0o600);
        } catch {
            // Best effort on platforms without POSIX modes.
        }
        renameSync(tmp, this.dbPath);
    }

    /**
     * Resolve the store key for a tool. With `domain` null the deprecated
     * tool-id-only lookup is performed; it returns null when the tool id is
     * pinned for more than one domain.
     * @private
     */
    _findKey(data, toolId, domain) {
        if (domain !== null && domain !== undefined) {
            const key = compositeKey(toolId, domain);
            return key in data.pinned_keys ? key : null;
        }
        const matches = Object.keys(data.pinned_keys).filter((k) => k.startsWith(`${toolId}@`));
        return matches.length === 1 ? matches[0] : null;
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
        const key = compositeKey(toolId, domain);

        if (key in data.pinned_keys) {
            return false; // Key already exists
        }

        data.pinned_keys[key] = {
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
     * Get the pinned public key for a tool at a domain.
     *
     * @param {string} toolId - Tool identifier
     * @param {string|null} [domain=null] - Tool provider domain. Always pass it:
     *   a pin recorded for a different domain is never returned.
     * @returns {string|null} PEM-encoded public key if pinned, null otherwise
     */
    getPinnedKey(toolId, domain = null) {
        const data = this._loadData();
        const key = this._findKey(data, toolId, domain);
        return key ? data.pinned_keys[key].public_key_pem : null;
    }

    /**
     * Check if a key is pinned for a tool at a domain.
     *
     * @param {string} toolId - Tool identifier
     * @param {string|null} [domain=null]
     * @returns {boolean} True if key is pinned, false otherwise
     */
    isKeyPinned(toolId, domain = null) {
        return this.getPinnedKey(toolId, domain) !== null;
    }

    /**
     * Update last verification timestamp for tool.
     *
     * @param {string} toolId - Tool identifier
     * @param {string|null} [domain=null]
     * @returns {boolean} True if updated successfully, false if tool not found
     */
    updateLastVerified(toolId, domain = null) {
        const data = this._loadData();
        const key = this._findKey(data, toolId, domain);
        if (!key) {
            return false;
        }
        data.pinned_keys[key].last_verified = new Date().toISOString();
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
            .map(([key, keyInfo]) => ({
                tool_id: key.slice(0, key.length - keyInfo.domain.length - 1),
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
     * @param {string|null} [domain=null]
     * @returns {boolean} True if removed successfully, false if not found
     */
    removePinnedKey(toolId, domain = null) {
        const data = this._loadData();
        const key = this._findKey(data, toolId, domain);
        if (!key) {
            return false;
        }
        delete data.pinned_keys[key];
        this._saveData(data);
        return true;
    }

    /**
     * Get complete information about pinned key.
     *
     * @param {string} toolId - Tool identifier
     * @param {string|null} [domain=null]
     * @returns {Object|null} Object with key information if found, null otherwise
     */
    getKeyInfo(toolId, domain = null) {
        const data = this._loadData();
        const key = this._findKey(data, toolId, domain);
        const keyInfo = key ? data.pinned_keys[key] : null;

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
            keyInfo.public_key_pem = this.getPinnedKey(keyInfo.tool_id, keyInfo.domain);
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
                if (overwrite && this.isKeyPinned(keyInfo.tool_id, keyInfo.domain)) {
                    this.removePinnedKey(keyInfo.tool_id, keyInfo.domain);
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
        
        // Check if key is already pinned for this tool at this domain
        const existingKey = this.getPinnedKey(toolId, domain);
        if (existingKey) {
            if (existingKey === publicKeyPem) {
                // Same key, just update verification time
                this.updateLastVerified(toolId, domain);
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
        // Revocation check (fail-closed): a key whose status cannot be
        // confirmed is never pinned automatically.
        if (!(await this._revocationChecker(publicKeyPem, domain))) {
            if (this.interactiveManager) {
                const decision = await this.interactiveManager.promptRevokedKey(
                    toolId, domain, publicKeyPem, { developer_name: developerName }
                );
                return decision === UserDecision.TEMPORARY_ACCEPT;
            }
            return false;
        }

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
        // Revocation check on the replacement key (fail-closed).
        if (!(await this._revocationChecker(newKeyPem, domain))) {
            if (this.interactiveManager) {
                const decision = await this.interactiveManager.promptRevokedKey(
                    toolId, domain, newKeyPem, { developer_name: developerName }
                );
                return decision === UserDecision.TEMPORARY_ACCEPT;
            }
            return false;
        }

        // In strict mode, always reject key changes
        if (this.mode === PinningMode.STRICT) {
            return false;
        }
        
        // Interactive prompt for key change
        if (this.interactiveManager) {
            const currentKeyInfo = this.getKeyInfo(toolId, domain);
            const developerInfo = { developer_name: developerName };

            const decision = await this.interactiveManager.promptKeyChange(
                toolId, domain, currentKeyPem, newKeyPem,
                currentKeyInfo, developerInfo
            );

            if (decision === UserDecision.ACCEPT) {
                // Remove old key and pin new one
                this.removePinnedKey(toolId, domain);
                return this.pinKey(toolId, newKeyPem, domain, developerName);
            } else if (decision === UserDecision.ALWAYS_TRUST) {
                this.setDomainPolicy(domain, PinningPolicy.ALWAYS_TRUST);
                this.removePinnedKey(toolId, domain);
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