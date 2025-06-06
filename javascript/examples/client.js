#!/usr/bin/env node
/**
 * Example client verification workflow for validating signed schemas.
 */

import { readFileSync, existsSync } from 'fs';
import { SchemaVerificationWorkflow } from '../src/utils.js';

// Mock .well-known server response for demonstration
function mockWellKnownServer(domain) {
    // In a real scenario, this would be fetched from the actual domain
    if (domain === "example.com") {
        // Load the demo well-known response if it exists
        try {
            const data = readFileSync("demo_well_known.json", "utf8");
            return JSON.parse(data);
        } catch (error) {
            return {
                schema_version: "1.0",
                developer_name: "Example Tool Developer",
                public_key_pem: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----",
                contact: "developer@example.com"
            };
        }
    }
    return null;
}

async function main() {
    console.log("SchemaPin Client Verification Example");
    console.log("=".repeat(45));
    
    // Check if we have demo files from tool developer example
    const schemaFile = "demo_schema_signed.json";
    const wellKnownFile = "demo_well_known.json";
    
    if (!existsSync(schemaFile)) {
        console.log("❌ demo_schema_signed.json not found!");
        console.log("Please run developer.js first to generate demo files.");
        return;
    }
    
    // Load signed schema
    console.log("\n1. Loading signed schema...");
    const schemaData = JSON.parse(readFileSync(schemaFile, "utf8"));
    
    const schema = schemaData.schema;
    const signature = schemaData.signature;
    
    console.log("✓ Signed schema loaded");
    console.log(`Schema: ${schema.name} - ${schema.description}`);
    console.log(`Signature: ${signature.substring(0, 32)}...`);
    
    // Load well-known response for mocking
    let wellKnownData = null;
    if (existsSync(wellKnownFile)) {
        wellKnownData = JSON.parse(readFileSync(wellKnownFile, "utf8"));
    }
    
    // Step 2: Initialize verification workflow
    console.log("\n2. Initializing verification workflow...");
    const verificationWorkflow = new SchemaVerificationWorkflow();
    console.log("✓ Verification workflow initialized");
    
    // Step 3: Mock the discovery service for demonstration
    console.log("\n3. Simulating public key discovery...");
    
    // Mock the discovery methods
    const originalGetPublicKeyPem = verificationWorkflow.discovery.getPublicKeyPem;
    const originalGetDeveloperInfo = verificationWorkflow.discovery.getDeveloperInfo;
    
    verificationWorkflow.discovery.getPublicKeyPem = async function(domain, timeout = 10000) {
        if (domain === "example.com" && wellKnownData) {
            return wellKnownData.public_key_pem;
        }
        return null;
    };
    
    verificationWorkflow.discovery.getDeveloperInfo = async function(domain, timeout = 10000) {
        if (domain === "example.com" && wellKnownData) {
            return {
                developer_name: wellKnownData.developer_name || "Unknown",
                schema_version: wellKnownData.schema_version || "1.0",
                contact: wellKnownData.contact || ""
            };
        }
        return null;
    };
    
    // Step 4: First-time verification (key pinning)
    console.log("\n4. First-time verification (TOFU - Trust On First Use)...");
    
    const result = await verificationWorkflow.verifySchema(
        schema,
        signature,
        "example.com/calculate_sum",
        "example.com",
        true // auto_pin
    );
    
    console.log(`✓ Verification result: ${JSON.stringify(result, null, 2)}`);
    
    if (result.valid) {
        console.log("✅ Schema signature is VALID");
        if (result.first_use) {
            console.log("🔑 Key pinned for future use");
            if (result.developer_info) {
                const devInfo = result.developer_info;
                console.log(`📋 Developer: ${devInfo.developer_name}`);
                console.log(`📧 Contact: ${devInfo.contact}`);
            }
        }
    } else {
        console.log("❌ Schema signature is INVALID");
        if (result.error) {
            console.log(`Error: ${result.error}`);
        }
    }
    
    // Step 5: Subsequent verification (using pinned key)
    console.log("\n5. Subsequent verification (using pinned key)...");
    
    const result2 = await verificationWorkflow.verifySchema(
        schema,
        signature,
        "example.com/calculate_sum",
        "example.com"
    );
    
    console.log(`✓ Verification result: ${JSON.stringify(result2, null, 2)}`);
    
    if (result2.valid) {
        console.log("✅ Schema signature is VALID (using pinned key)");
        console.log("🔒 Key was already pinned - no network request needed");
    } else {
        console.log("❌ Schema signature is INVALID");
    }
    
    // Step 6: Show pinned keys
    console.log("\n6. Listing pinned keys...");
    const pinnedKeys = verificationWorkflow.pinning.listPinnedKeys();
    
    if (pinnedKeys.length > 0) {
        console.log("✓ Pinned keys:");
        for (const keyInfo of pinnedKeys) {
            console.log(`  - Tool: ${keyInfo.tool_id}`);
            console.log(`    Domain: ${keyInfo.domain}`);
            console.log(`    Developer: ${keyInfo.developer_name}`);
            console.log(`    Pinned: ${keyInfo.pinned_at}`);
        }
    } else {
        console.log("No keys pinned yet");
    }
    
    // Step 7: Demonstrate invalid signature detection
    console.log("\n7. Testing invalid signature detection...");
    
    // Modify the signature to make it invalid
    const invalidSignature = signature.slice(0, -4) + "XXXX";
    
    const result3 = await verificationWorkflow.verifySchema(
        schema,
        invalidSignature,
        "example.com/calculate_sum",
        "example.com"
    );
    
    if (!result3.valid) {
        console.log("✅ Invalid signature correctly detected");
        console.log("🛡️ SchemaPin successfully prevented use of tampered schema");
    } else {
        console.log("❌ Invalid signature was not detected (this should not happen)");
    }
    
    console.log("\n" + "=".repeat(45));
    console.log("Client verification workflow complete!");
    console.log("\nKey takeaways:");
    console.log("✓ Valid signatures are accepted");
    console.log("✓ Invalid signatures are rejected");
    console.log("✓ Keys are pinned on first use (TOFU)");
    console.log("✓ Subsequent verifications use pinned keys");
    console.log("✓ Network requests only needed for new tools");
}

if (import.meta.url === `file://${process.argv[1]}`) {
    main().catch(console.error);
}