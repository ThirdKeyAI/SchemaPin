/**
 * Interactive key pinning interface for user prompts and decisions.
 */

import { createHash } from 'crypto';

/**
 * Types of interactive prompts for key pinning.
 */
export const PromptType = {
    FIRST_TIME_KEY: 'first_time_key',
    KEY_CHANGE: 'key_change',
    REVOKED_KEY: 'revoked_key',
    EXPIRED_KEY: 'expired_key'
};

/**
 * User decisions for key pinning prompts.
 */
export const UserDecision = {
    ACCEPT: 'accept',
    REJECT: 'reject',
    ALWAYS_TRUST: 'always_trust',
    NEVER_TRUST: 'never_trust',
    TEMPORARY_ACCEPT: 'temporary_accept'
};

/**
 * Information about a public key for display to users.
 */
export class KeyInfo {
    constructor({
        fingerprint,
        pemData,
        domain,
        developerName = null,
        pinnedAt = null,
        lastVerified = null,
        isRevoked = false
    }) {
        this.fingerprint = fingerprint;
        this.pemData = pemData;
        this.domain = domain;
        this.developerName = developerName;
        this.pinnedAt = pinnedAt;
        this.lastVerified = lastVerified;
        this.isRevoked = isRevoked;
    }
}

/**
 * Context information for interactive prompts.
 */
export class PromptContext {
    constructor({
        promptType,
        toolId,
        domain,
        currentKey = null,
        newKey = null,
        developerInfo = null,
        securityWarning = null
    }) {
        this.promptType = promptType;
        this.toolId = toolId;
        this.domain = domain;
        this.currentKey = currentKey;
        this.newKey = newKey;
        this.developerInfo = developerInfo;
        this.securityWarning = securityWarning;
    }
}

/**
 * Abstract base class for interactive key pinning handlers.
 */
export class InteractiveHandler {
    /**
     * Prompt user for decision on key pinning.
     * 
     * @param {PromptContext} context - Context information for the prompt
     * @returns {Promise<string>} User's decision
     */
    async promptUser(context) {
        throw new Error('promptUser must be implemented by subclass');
    }

    /**
     * Format key information for display.
     * 
     * @param {KeyInfo} keyInfo - Key information to display
     * @returns {string} Formatted string for display
     */
    displayKeyInfo(keyInfo) {
        throw new Error('displayKeyInfo must be implemented by subclass');
    }

    /**
     * Display security warning to user.
     * 
     * @param {string} warning - Warning message to display
     */
    displaySecurityWarning(warning) {
        throw new Error('displaySecurityWarning must be implemented by subclass');
    }
}

/**
 * Console-based interactive handler for key pinning.
 */
export class ConsoleInteractiveHandler extends InteractiveHandler {
    constructor() {
        super();
        // For Node.js readline interface
        this.readline = null;
        try {
            const readline = require('readline');
            this.readline = readline;
        } catch (e) {
            // Browser environment or readline not available
        }
    }

    /**
     * Prompt user via console for key pinning decision.
     * 
     * @param {PromptContext} context - Context information
     * @returns {Promise<string>} User's decision
     */
    async promptUser(context) {
        console.log('\n' + '='.repeat(60));
        console.log('SCHEMAPIN SECURITY PROMPT');
        console.log('='.repeat(60));

        switch (context.promptType) {
        case PromptType.FIRST_TIME_KEY:
            this._displayFirstTimePrompt(context);
            break;
        case PromptType.KEY_CHANGE:
            this._displayKeyChangePrompt(context);
            break;
        case PromptType.REVOKED_KEY:
            this._displayRevokedKeyPrompt(context);
            break;
        }

        return await this._getUserChoice(context.promptType);
    }

    /**
     * Format key information for console display.
     * 
     * @param {KeyInfo} keyInfo - Key information to display
     * @returns {string} Formatted string
     */
    displayKeyInfo(keyInfo) {
        const infoLines = [
            `Fingerprint: ${keyInfo.fingerprint}`,
            `Domain: ${keyInfo.domain}`
        ];

        if (keyInfo.developerName) {
            infoLines.push(`Developer: ${keyInfo.developerName}`);
        }

        if (keyInfo.pinnedAt) {
            infoLines.push(`Pinned: ${keyInfo.pinnedAt}`);
        }

        if (keyInfo.lastVerified) {
            infoLines.push(`Last Verified: ${keyInfo.lastVerified}`);
        }

        if (keyInfo.isRevoked) {
            infoLines.push('⚠️  STATUS: REVOKED');
        }

        return infoLines.join('\n');
    }

    /**
     * Display security warning to console.
     * 
     * @param {string} warning - Warning message
     */
    displaySecurityWarning(warning) {
        console.log(`\n⚠️  SECURITY WARNING: ${warning}\n`);
    }

    /**
     * Display first-time key encounter prompt.
     * @private
     */
    _displayFirstTimePrompt(context) {
        console.log(`\nFirst-time key encounter for tool: ${context.toolId}`);
        console.log(`Domain: ${context.domain}`);

        if (context.developerInfo) {
            console.log(`Developer: ${context.developerInfo.developer_name || 'Unknown'}`);
        }

        if (context.newKey) {
            console.log('\nNew Key Information:');
            console.log(this.displayKeyInfo(context.newKey));
        }

        console.log('\nThis is the first time you\'re encountering this tool.');
        console.log('Do you want to pin this key for future verification?');
    }

    /**
     * Display key change prompt.
     * @private
     */
    _displayKeyChangePrompt(context) {
        console.log(`\n⚠️  KEY CHANGE DETECTED for tool: ${context.toolId}`);
        console.log(`Domain: ${context.domain}`);

        if (context.currentKey) {
            console.log('\nCurrently Pinned Key:');
            console.log(this.displayKeyInfo(context.currentKey));
        }

        if (context.newKey) {
            console.log('\nNew Key Being Offered:');
            console.log(this.displayKeyInfo(context.newKey));
        }

        console.log('\n⚠️  The tool is using a different key than previously pinned!');
        console.log('This could indicate a legitimate key rotation or a security compromise.');
    }

    /**
     * Display revoked key prompt.
     * @private
     */
    _displayRevokedKeyPrompt(context) {
        console.log(`\n🚨 REVOKED KEY DETECTED for tool: ${context.toolId}`);
        console.log(`Domain: ${context.domain}`);

        if (context.currentKey) {
            console.log('\nRevoked Key Information:');
            console.log(this.displayKeyInfo(context.currentKey));
        }

        console.log('\n🚨 This key has been marked as revoked by the developer!');
        console.log('Using this tool is NOT RECOMMENDED.');

        if (context.securityWarning) {
            this.displaySecurityWarning(context.securityWarning);
        }
    }

    /**
     * Get user's choice from console input.
     * @private
     */
    async _getUserChoice(promptType) {
        if (!this.readline) {
            // Fallback for browser or when readline is not available
            console.log('Interactive prompts not available in this environment');
            return UserDecision.REJECT;
        }

        const rl = this.readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });

        try {
            let choices, prompt, defaultChoice;

            if (promptType === PromptType.REVOKED_KEY) {
                choices = {
                    'r': UserDecision.REJECT,
                    'n': UserDecision.NEVER_TRUST
                };
                prompt = '\nChoices:\n  r) Reject (recommended)\n  n) Never trust this domain\nChoice [r]: ';
                defaultChoice = UserDecision.REJECT;
            } else {
                choices = {
                    'a': UserDecision.ACCEPT,
                    'r': UserDecision.REJECT,
                    't': UserDecision.ALWAYS_TRUST,
                    'n': UserDecision.NEVER_TRUST,
                    'o': UserDecision.TEMPORARY_ACCEPT
                };
                prompt = '\nChoices:\n' +
                        '  a) Accept and pin this key\n' +
                        '  r) Reject this key\n' +
                        '  t) Always trust this domain\n' +
                        '  n) Never trust this domain\n' +
                        '  o) Accept once (temporary)\n' +
                        'Choice [r]: ';
                defaultChoice = UserDecision.REJECT;
            }

            while (true) {
                const answer = await new Promise((resolve) => {
                    rl.question(prompt, resolve);
                });

                const choice = answer.toLowerCase().trim();
                
                if (!choice) {
                    return defaultChoice;
                }
                
                if (choice in choices) {
                    return choices[choice];
                }
                
                console.log('Invalid choice. Please try again.');
            }
        } finally {
            rl.close();
        }
    }
}

/**
 * Callback-based interactive handler for custom implementations.
 */
export class CallbackInteractiveHandler extends InteractiveHandler {
    /**
     * Initialize callback handler.
     * 
     * @param {Function} promptCallback - Function to handle user prompts
     * @param {Function} displayCallback - Optional function to display messages
     */
    constructor(promptCallback, displayCallback = console.log) {
        super();
        this.promptCallback = promptCallback;
        this.displayCallback = displayCallback;
    }

    /**
     * Prompt user via callback function.
     * 
     * @param {PromptContext} context - Context information
     * @returns {Promise<string>} User's decision
     */
    async promptUser(context) {
        return await this.promptCallback(context);
    }

    /**
     * Format key information for display.
     * 
     * @param {KeyInfo} keyInfo - Key information
     * @returns {string} Formatted string
     */
    displayKeyInfo(keyInfo) {
        const infoParts = [
            `Fingerprint: ${keyInfo.fingerprint}`,
            `Domain: ${keyInfo.domain}`
        ];

        if (keyInfo.developerName) {
            infoParts.push(`Developer: ${keyInfo.developerName}`);
        }

        if (keyInfo.isRevoked) {
            infoParts.push('STATUS: REVOKED');
        }

        return infoParts.join(' | ');
    }

    /**
     * Display security warning via callback.
     * 
     * @param {string} warning - Warning message
     */
    displaySecurityWarning(warning) {
        if (this.displayCallback) {
            this.displayCallback(`SECURITY WARNING: ${warning}`);
        }
    }
}

/**
 * Manages interactive key pinning with user prompts.
 */
export class InteractivePinningManager {
    /**
     * Initialize interactive pinning manager.
     * 
     * @param {InteractiveHandler} handler - Interactive handler for user prompts
     */
    constructor(handler = null) {
        this.handler = handler || new ConsoleInteractiveHandler();
    }

    /**
     * Create KeyInfo object from public key data.
     * 
     * @param {string} publicKeyPem - PEM-encoded public key
     * @param {string} domain - Tool provider domain
     * @param {string} developerName - Optional developer name
     * @param {string} pinnedAt - Optional pinning timestamp
     * @param {string} lastVerified - Optional last verification timestamp
     * @param {boolean} isRevoked - Whether key is revoked
     * @returns {KeyInfo} KeyInfo object
     */
    createKeyInfo(publicKeyPem, domain, developerName = null, 
        pinnedAt = null, lastVerified = null, isRevoked = false) {
        let fingerprint;
        try {
            fingerprint = this._calculateKeyFingerprint(publicKeyPem);
        } catch (error) {
            fingerprint = 'Invalid key';
        }

        return new KeyInfo({
            fingerprint,
            pemData: publicKeyPem,
            domain,
            developerName,
            pinnedAt,
            lastVerified,
            isRevoked
        });
    }

    /**
     * Prompt user for first-time key encounter.
     * 
     * @param {string} toolId - Tool identifier
     * @param {string} domain - Tool provider domain
     * @param {string} publicKeyPem - PEM-encoded public key
     * @param {Object} developerInfo - Optional developer information
     * @returns {Promise<string>} User's decision
     */
    async promptFirstTimeKey(toolId, domain, publicKeyPem, developerInfo = null) {
        const newKey = this.createKeyInfo(
            publicKeyPem, 
            domain, 
            developerInfo?.developer_name || null
        );

        const context = new PromptContext({
            promptType: PromptType.FIRST_TIME_KEY,
            toolId,
            domain,
            newKey,
            developerInfo
        });

        return await this.handler.promptUser(context);
    }

    /**
     * Prompt user for key change.
     * 
     * @param {string} toolId - Tool identifier
     * @param {string} domain - Tool provider domain
     * @param {string} currentKeyPem - Currently pinned key
     * @param {string} newKeyPem - New key being offered
     * @param {Object} currentKeyInfo - Optional current key metadata
     * @param {Object} developerInfo - Optional developer information
     * @returns {Promise<string>} User's decision
     */
    async promptKeyChange(toolId, domain, currentKeyPem, newKeyPem, 
        currentKeyInfo = null, developerInfo = null) {
        const currentKey = this.createKeyInfo(
            currentKeyPem,
            domain,
            currentKeyInfo?.developer_name || null,
            currentKeyInfo?.pinned_at || null,
            currentKeyInfo?.last_verified || null
        );

        const newKey = this.createKeyInfo(
            newKeyPem,
            domain,
            developerInfo?.developer_name || null
        );

        const context = new PromptContext({
            promptType: PromptType.KEY_CHANGE,
            toolId,
            domain,
            currentKey,
            newKey,
            developerInfo
        });

        return await this.handler.promptUser(context);
    }

    /**
     * Prompt user for revoked key detection.
     * 
     * @param {string} toolId - Tool identifier
     * @param {string} domain - Tool provider domain
     * @param {string} revokedKeyPem - Revoked key
     * @param {Object} keyInfo - Optional key metadata
     * @returns {Promise<string>} User's decision
     */
    async promptRevokedKey(toolId, domain, revokedKeyPem, keyInfo = null) {
        const revokedKey = this.createKeyInfo(
            revokedKeyPem,
            domain,
            keyInfo?.developer_name || null,
            keyInfo?.pinned_at || null,
            keyInfo?.last_verified || null,
            true // isRevoked
        );

        const context = new PromptContext({
            promptType: PromptType.REVOKED_KEY,
            toolId,
            domain,
            currentKey: revokedKey,
            securityWarning: 'This key has been revoked by the developer. Do not use this tool.'
        });

        return await this.handler.promptUser(context);
    }

    /**
     * Calculate key fingerprint from PEM data.
     * @private
     */
    _calculateKeyFingerprint(publicKeyPem) {
        // This is a simplified version - in a real implementation,
        // you'd want to properly parse the PEM and extract the DER bytes
        const hash = createHash('sha256');
        hash.update(publicKeyPem);
        return `sha256:${hash.digest('hex')}`;
    }
}