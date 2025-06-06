/**
 * Key pinning storage and management for Trust-On-First-Use (TOFU).
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { homedir } from 'os';

/**
 * Manages key pinning storage using JSON file.
 */
export class KeyPinning {
    /**
     * Initialize key pinning storage.
     * 
     * @param {string|null} dbPath - Path to JSON storage file. If null, uses default location.
     */
    constructor(dbPath = null) {
        if (dbPath === null) {
            const homeDir = homedir();
            dbPath = join(homeDir, '.schemapin', 'pinned_keys.json');
        }
        
        this.dbPath = dbPath;
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
            this._saveData({});
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
            return JSON.parse(data);
        } catch (error) {
            return {};
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
        
        if (toolId in data) {
            return false; // Key already exists
        }
        
        data[toolId] = {
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
        const keyInfo = data[toolId];
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
        
        if (!(toolId in data)) {
            return false;
        }
        
        data[toolId].last_verified = new Date().toISOString();
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
        return Object.entries(data)
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
        
        if (!(toolId in data)) {
            return false;
        }
        
        delete data[toolId];
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
        const keyInfo = data[toolId];
        
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
}