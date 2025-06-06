#!/usr/bin/env node
/**
 * Example tool developer workflow for signing schemas.
 */

import { writeFileSync } from 'fs';
import { KeyManager } from '../src/crypto.js';
import { SchemaSigningWorkflow, createWellKnownResponse } from '../src/utils.js';

function main() {
    console.log("SchemaPin Tool Developer Example");
    console.log("=" .repeat(40));
    
    // Step 1: Generate key pair
    console.log("\n1. Generating ECDSA P-256 key pair...");
    const { privateKey, publicKey } = KeyManager.generateKeypair();
    
    const privateKeyPem = KeyManager.exportPrivateKeyPem(privateKey);
    const publicKeyPem = KeyManager.exportPublicKeyPem(publicKey);
    
    console.log("✓ Key pair generated");
    
    // Step 2: Create sample tool schema
    console.log("\n2. Creating sample tool schema...");
    const sampleSchema = {
        name: "calculate_sum",
        description: "Calculates the sum of two numbers",
        parameters: {
            type: "object",
            properties: {
                a: {
                    type: "number",
                    description: "First number"
                },
                b: {
                    type: "number", 
                    description: "Second number"
                }
            },
            required: ["a", "b"]
        }
    };
    
    console.log("✓ Sample schema created");
    console.log(`Schema: ${JSON.stringify(sampleSchema, null, 2)}`);
    
    // Step 3: Sign the schema
    console.log("\n3. Signing schema...");
    const signingWorkflow = new SchemaSigningWorkflow(privateKeyPem);
    const signature = signingWorkflow.signSchema(sampleSchema);
    
    console.log("✓ Schema signed");
    console.log(`Signature: ${signature}`);
    
    // Step 4: Create .well-known response
    console.log("\n4. Creating .well-known/schemapin.json response...");
    const wellKnownResponse = createWellKnownResponse(
        publicKeyPem,
        "Example Tool Developer",
        "developer@example.com"
    );
    
    console.log("✓ .well-known response created");
    console.log(`.well-known content: ${JSON.stringify(wellKnownResponse, null, 2)}`);
    
    // Step 5: Save files for demonstration
    console.log("\n5. Saving demonstration files...");
    
    // Save private key (in real use, keep this secure!)
    writeFileSync("demo_private_key.pem", privateKeyPem);
    
    // Save schema with signature
    const schemaWithSignature = {
        schema: sampleSchema,
        signature: signature
    };
    writeFileSync("demo_schema_signed.json", JSON.stringify(schemaWithSignature, null, 2));
    
    // Save .well-known response
    writeFileSync("demo_well_known.json", JSON.stringify(wellKnownResponse, null, 2));
    
    console.log("✓ Files saved:");
    console.log("  - demo_private_key.pem (keep secure!)");
    console.log("  - demo_schema_signed.json");
    console.log("  - demo_well_known.json");
    
    console.log("\n" + "=".repeat(40));
    console.log("Tool developer workflow complete!");
    console.log("\nNext steps:");
    console.log("1. Host demo_well_known.json at https://yourdomain.com/.well-known/schemapin.json");
    console.log("2. Distribute demo_schema_signed.json with your tool");
    console.log("3. Keep demo_private_key.pem secure and use it to sign future schema updates");
}

if (import.meta.url === `file://${process.argv[1]}`) {
    main();
}