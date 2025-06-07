#!/usr/bin/env node
/**
 * Interactive Key Pinning Demo
 * 
 * This example demonstrates how to use SchemaPin's interactive key pinning
 * functionality to prompt users for key decisions.
 */

import { 
    InteractivePinningManager,
    CallbackInteractiveHandler,
    UserDecision,
    PromptType
} from '../src/interactive.js';
import { KeyPinning, PinningMode, PinningPolicy } from '../src/pinning.js';
import { SchemaPinCore } from '../src/core.js';
import { readFileSync, writeFileSync, existsSync, unlinkSync, mkdirSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

/**
 * Demonstrate callback-based interactive pinning.
 */
async function demoCallbackInteractivePinning() {
    console.log('\n=== Callback Interactive Pinning Demo ===\n');
    
    // Create temporary database
    const tempDir = join(tmpdir(), `schemapin-demo-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
    const dbPath = join(tempDir, 'demo_pinning.json');
    
    try {
        // Custom callback function
        const customPromptHandler = async (context) => {
            console.log(`Custom handler called for: ${context.toolId}`);
            console.log(`Prompt type: ${context.promptType}`);
            
            if (context.promptType === PromptType.FIRST_TIME_KEY) {
                console.log('Auto-accepting first-time key...');
                return UserDecision.ACCEPT;
            } else if (context.promptType === PromptType.KEY_CHANGE) {
                console.log('Auto-rejecting key change...');
                return UserDecision.REJECT;
            } else {
                console.log('Auto-rejecting revoked key...');
                return UserDecision.REJECT;
            }
        };
        
        // Create callback handler
        const callbackHandler = new CallbackInteractiveHandler(customPromptHandler);
        
        // Initialize pinning with callback handler
        const pinning = new KeyPinning(dbPath, PinningMode.INTERACTIVE, callbackHandler);
        
        // Demo key (simplified for demo)
        const publicKeyPem = '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtest...\n-----END PUBLIC KEY-----';
        
        // Demo tool information
        const toolId = 'demo-api-client';
        const domain = 'api.example.com';
        const developerName = 'API Corp';
        
        console.log(`Tool: ${toolId}`);
        console.log(`Domain: ${domain}`);
        console.log(`Developer: ${developerName}`);
        console.log();
        
        // Pin the key (will use callback)
        const result = await pinning.interactivePinKey(
            toolId, publicKeyPem, domain, developerName
        );
        
        console.log(`Result: ${result ? 'Accepted' : 'Rejected'}`);
        console.log(`Key pinned: ${pinning.isKeyPinned(toolId)}`);
        
        // Test key change (should be rejected by callback)
        if (pinning.isKeyPinned(toolId)) {
            console.log('\n--- Testing Key Change ---');
            
            const newPublicKeyPem = '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnew...\n-----END PUBLIC KEY-----';
            
            const changeResult = await pinning.interactivePinKey(
                toolId, newPublicKeyPem, domain, developerName
            );
            
            console.log(`Key change result: ${changeResult ? 'Accepted' : 'Rejected'}`);
        }
    
    } finally {
        // Cleanup
        if (existsSync(dbPath)) {
            unlinkSync(dbPath);
        }
        try {
            require('fs').rmSync(tempDir, { recursive: true });
        } catch (e) {
            // Ignore cleanup errors
        }
    }
}

/**
 * Demonstrate domain-based pinning policies.
 */
async function demoDomainPolicies() {
    console.log('\n=== Domain Policies Demo ===\n');
    
    // Create temporary database
    const tempDir = join(tmpdir(), `schemapin-demo-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
    const dbPath = join(tempDir, 'demo_pinning.json');
    
    try {
        const pinning = new KeyPinning(dbPath, PinningMode.INTERACTIVE);
        
        // Demo key
        const publicKeyPem = '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtest...\n-----END PUBLIC KEY-----';
        
        // Test different domain policies
        const domains = [
            ['trusted.example.com', PinningPolicy.ALWAYS_TRUST],
            ['untrusted.example.com', PinningPolicy.NEVER_TRUST],
            ['normal.example.com', PinningPolicy.DEFAULT]
        ];
        
        for (const [domain, policy] of domains) {
            console.log(`Testing domain: ${domain} with policy: ${policy}`);
            
            // Set domain policy
            pinning.setDomainPolicy(domain, policy);
            
            // Try to pin key
            const toolId = `tool-${domain.split('.')[0]}`;
            const result = await pinning.interactivePinKey(
                toolId, publicKeyPem, domain, 'Test Developer'
            );
            
            console.log(`  Result: ${result ? 'Accepted' : 'Rejected'}`);
            console.log(`  Key pinned: ${pinning.isKeyPinned(toolId)}`);
            console.log();
        }
    
    } finally {
        // Cleanup
        if (existsSync(dbPath)) {
            unlinkSync(dbPath);
        }
        try {
            require('fs').rmSync(tempDir, { recursive: true });
        } catch (e) {
            // Ignore cleanup errors
        }
    }
}

/**
 * Demonstrate automatic mode pinning.
 */
async function demoAutomaticMode() {
    console.log('\n=== Automatic Mode Demo ===\n');
    
    // Create temporary database
    const tempDir = join(tmpdir(), `schemapin-demo-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
    const dbPath = join(tempDir, 'demo_pinning.json');
    
    try {
        const pinning = new KeyPinning(dbPath, PinningMode.AUTOMATIC);
        
        // Demo key
        const publicKeyPem = '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtest...\n-----END PUBLIC KEY-----';
        
        // Demo tool information
        const toolId = 'auto-tool';
        const domain = 'auto.example.com';
        const developerName = 'Auto Corp';
        
        console.log(`Tool: ${toolId}`);
        console.log(`Domain: ${domain}`);
        console.log(`Developer: ${developerName}`);
        console.log();
        
        // Should pin automatically without prompts
        console.log('Attempting automatic pinning...');
        const result = await pinning.interactivePinKey(
            toolId, publicKeyPem, domain, developerName
        );
        
        console.log(`Result: ${result ? 'Accepted' : 'Rejected'}`);
        console.log(`Key pinned: ${pinning.isKeyPinned(toolId)}`);
        
        // Test same key again (should update verification time)
        console.log('\nTesting same key again...');
        const sameKeyResult = await pinning.interactivePinKey(
            toolId, publicKeyPem, domain, developerName
        );
        
        console.log(`Same key result: ${sameKeyResult ? 'Accepted' : 'Rejected'}`);
    
    } finally {
        // Cleanup
        if (existsSync(dbPath)) {
            unlinkSync(dbPath);
        }
        try {
            require('fs').rmSync(tempDir, { recursive: true });
        } catch (e) {
            // Ignore cleanup errors
        }
    }
}

/**
 * Demonstrate strict mode behavior.
 */
async function demoStrictMode() {
    console.log('\n=== Strict Mode Demo ===\n');
    
    // Create temporary database
    const tempDir = join(tmpdir(), `schemapin-demo-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
    const dbPath = join(tempDir, 'demo_pinning.json');
    
    try {
        const pinning = new KeyPinning(dbPath, PinningMode.STRICT);
        
        // Demo keys
        const publicKeyPem1 = '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtest1...\n-----END PUBLIC KEY-----';
        const publicKeyPem2 = '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtest2...\n-----END PUBLIC KEY-----';
        
        // Demo tool information
        const toolId = 'strict-tool';
        const domain = 'strict.example.com';
        const developerName = 'Strict Corp';
        
        console.log(`Tool: ${toolId}`);
        console.log(`Domain: ${domain}`);
        console.log(`Mode: STRICT`);
        console.log();
        
        // Pin initial key manually (strict mode allows initial pinning)
        console.log('Manually pinning initial key...');
        const initialPin = pinning.pinKey(toolId, publicKeyPem1, domain, developerName);
        console.log(`Initial pin result: ${initialPin}`);
        
        // Try to change key (should be rejected in strict mode)
        console.log('\nAttempting key change in strict mode...');
        const changeResult = await pinning.interactivePinKey(
            toolId, publicKeyPem2, domain, developerName
        );
        
        console.log(`Key change result: ${changeResult ? 'Accepted' : 'Rejected'}`);
        console.log(`Current pinned key matches original: ${pinning.getPinnedKey(toolId) === publicKeyPem1}`);
    
    } finally {
        // Cleanup
        if (existsSync(dbPath)) {
            unlinkSync(dbPath);
        }
        try {
            require('fs').rmSync(tempDir, { recursive: true });
        } catch (e) {
            // Ignore cleanup errors
        }
    }
}

/**
 * Demonstrate schema verification with interactive pinning.
 */
async function demoSchemaVerificationWithInteractivePinning() {
    console.log('\n=== Schema Verification with Interactive Pinning Demo ===\n');
    
    // Create temporary database
    const tempDir = join(tmpdir(), `schemapin-demo-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
    const dbPath = join(tempDir, 'demo_pinning.json');
    
    try {
        // Initialize components
        const pinning = new KeyPinning(dbPath, PinningMode.AUTOMATIC);
        
        // Demo key (in real implementation, you'd generate actual keys)
        const publicKeyPem = '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtest...\n-----END PUBLIC KEY-----';
        
        // Create demo schema
        const schema = {
            name: 'calculate_sum',
            description: 'Calculate the sum of two numbers',
            parameters: {
                a: { type: 'number', description: 'First number' },
                b: { type: 'number', description: 'Second number' }
            }
        };
        
        // Canonicalize schema (for demo purposes)
        const canonicalSchema = SchemaPinCore.canonicalizeSchema(schema);
        const schemaHash = SchemaPinCore.hashCanonical(canonicalSchema);
        
        console.log('Schema to verify:');
        console.log(JSON.stringify(schema, null, 2));
        console.log(`\nCanonical form: ${canonicalSchema}`);
        console.log(`Schema hash: ${schemaHash.toString('hex').substring(0, 16)}...`);
        
        // Tool information
        const toolId = 'math-calculator';
        const domain = 'mathtools.example.com';
        const developerName = 'Math Tools LLC';
        
        // Verify with interactive pinning
        console.log(`\nVerifying schema for tool: ${toolId}`);
        
        // Handle key pinning
        const pinResult = await pinning.verifyWithInteractivePinning(
            toolId, domain, publicKeyPem, developerName
        );
        
        if (pinResult) {
            console.log('✅ Key pinning successful');
            console.log('🎉 Schema can be trusted (signature verification would happen here)!');
        } else {
            console.log('❌ Key pinning failed - schema cannot be trusted');
        }
        
        // Show pinned keys
        console.log('\nPinned keys in database:');
        const pinnedKeys = pinning.listPinnedKeys();
        if (pinnedKeys.length === 0) {
            console.log('  (none)');
        } else {
            pinnedKeys.forEach(keyInfo => {
                console.log(`  - ${keyInfo.tool_id} (${keyInfo.domain})`);
            });
        }
    
    } finally {
        // Cleanup
        if (existsSync(dbPath)) {
            unlinkSync(dbPath);
        }
        try {
            require('fs').rmSync(tempDir, { recursive: true });
        } catch (e) {
            // Ignore cleanup errors
        }
    }
}

/**
 * Demonstrate temporary accept functionality.
 */
async function demoTemporaryAccept() {
    console.log('\n=== Temporary Accept Demo ===\n');
    
    // Create temporary database
    const tempDir = join(tmpdir(), `schemapin-demo-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
    const dbPath = join(tempDir, 'demo_pinning.json');
    
    try {
        // Custom callback that returns temporary accept
        const tempAcceptHandler = async (context) => {
            console.log(`Handler called for: ${context.toolId}`);
            console.log('Returning TEMPORARY_ACCEPT...');
            return UserDecision.TEMPORARY_ACCEPT;
        };
        
        const callbackHandler = new CallbackInteractiveHandler(tempAcceptHandler);
        const pinning = new KeyPinning(dbPath, PinningMode.INTERACTIVE, callbackHandler);
        
        const publicKeyPem = '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtest...\n-----END PUBLIC KEY-----';
        const toolId = 'temp-tool';
        const domain = 'temp.example.com';
        
        console.log(`Tool: ${toolId}`);
        console.log(`Domain: ${domain}`);
        console.log();
        
        // Use temporary accept
        const result = await pinning.interactivePinKey(
            toolId, publicKeyPem, domain, 'Temp Corp'
        );
        
        console.log(`Verification result: ${result ? 'Allowed' : 'Denied'}`);
        console.log(`Key permanently pinned: ${pinning.isKeyPinned(toolId)}`);
        console.log('Note: Temporary accept allows verification without permanent pinning');
    
    } finally {
        // Cleanup
        if (existsSync(dbPath)) {
            unlinkSync(dbPath);
        }
        try {
            require('fs').rmSync(tempDir, { recursive: true });
        } catch (e) {
            // Ignore cleanup errors
        }
    }
}

/**
 * Run all interactive pinning demos.
 */
async function main() {
    console.log('SchemaPin Interactive Key Pinning Demo');
    console.log('='.repeat(50));
    
    await demoCallbackInteractivePinning();
    await demoDomainPolicies();
    await demoAutomaticMode();
    await demoStrictMode();
    await demoSchemaVerificationWithInteractivePinning();
    await demoTemporaryAccept();
    
    console.log('\n🎉 All demos completed successfully!');
}

// Run demos if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
    main().catch(console.error);
}

export {
    demoCallbackInteractivePinning,
    demoDomainPolicies,
    demoAutomaticMode,
    demoStrictMode,
    demoSchemaVerificationWithInteractivePinning,
    demoTemporaryAccept
};