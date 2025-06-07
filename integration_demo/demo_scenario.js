#!/usr/bin/env node
/**
 * SchemaPin Integration Demo - JavaScript Implementation
 * 
 * Demonstrates cross-language integration scenarios between JavaScript and Python
 * implementations of SchemaPin.
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { spawn } from 'child_process';
import chalk from 'chalk';
import inquirer from 'inquirer';

// Import SchemaPin modules
import { KeyManager, SignatureManager } from '../javascript/src/crypto.js';
import { SchemaSigningWorkflow, SchemaVerificationWorkflow } from '../javascript/src/utils.js';
import { InteractivePinningManager, ConsoleInteractiveHandler } from '../javascript/src/interactive.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

class JSDemo {
    constructor() {
        this.baseDir = __dirname;
        this.testDataDir = join(this.baseDir, 'test_data');
        this.keysDir = join(this.testDataDir, 'keys');
        this.signedSchemasDir = join(this.testDataDir, 'signed_schemas');
        this.verificationResultsDir = join(this.testDataDir, 'verification_results');
        this.sampleSchemasDir = join(this.baseDir, 'sample_schemas');
        
        this.ensureDirectories();
    }
    
    ensureDirectories() {
        const dirs = [this.testDataDir, this.keysDir, this.signedSchemasDir, this.verificationResultsDir];
        dirs.forEach(dir => {
            if (!existsSync(dir)) {
                mkdirSync(dir, { recursive: true });
            }
        });
    }
    
    loadSampleSchema(schemaName) {
        const schemaFile = join(this.sampleSchemasDir, `${schemaName}.json`);
        if (!existsSync(schemaFile)) {
            throw new Error(`Sample schema not found: ${schemaFile}`);
        }
        return JSON.parse(readFileSync(schemaFile, 'utf8'));
    }
    
    async scenario2JSSignsPythonVerifies() {
        console.log(chalk.blue('\n🧪 Scenario 2: JavaScript Signs → Python Verifies (Interactive)'));
        console.log(chalk.blue('=' .repeat(70)));
        
        // Load schema and keys
        const schema = this.loadSampleSchema('api_endpoint');
        const privateKeyFile = join(this.keysDir, 'bob.example.com_private.pem');
        
        if (!existsSync(privateKeyFile)) {
            console.log(chalk.yellow('⚠️  Demo environment not set up. Run Python demo with --setup first.'));
            return false;
        }
        
        const privateKeyPem = readFileSync(privateKeyFile, 'utf8');
        
        // Sign schema with JavaScript
        console.log(chalk.green('📝 Signing schema with JavaScript...'));
        const signingWorkflow = new SchemaSigningWorkflow(privateKeyPem);
        const signature = signingWorkflow.signSchema(schema);
        
        // Create signed schema
        const signedSchema = {
            schema: schema,
            signature: signature,
            signed_at: new Date().toISOString(),
            metadata: {
                developer: "Bob Industries",
                domain: "bob.example.com",
                tool_id: "bob.example.com/user_api"
            }
        };
        
        const signedFile = join(this.signedSchemasDir, 'scenario2_js_signed.json');
        writeFileSync(signedFile, JSON.stringify(signedSchema, null, 2));
        
        console.log(chalk.green(`✅ Schema signed and saved to ${signedFile}`));
        console.log(chalk.gray(`   Signature: ${signature.substring(0, 50)}...`));
        
        // Call Python verification
        console.log(chalk.blue('🔍 Calling Python for verification...'));
        
        try {
            const pythonResult = await this.runPythonVerification(signedFile);
            if (pythonResult.success) {
                console.log(chalk.green('✅ Python verification successful!'));
                console.log(chalk.gray(`   Result: ${JSON.stringify(pythonResult.data, null, 2)}`));
            } else {
                console.log(chalk.red(`❌ Python verification failed: ${pythonResult.error}`));
            }
        } catch (error) {
            console.log(chalk.red(`❌ Python verification error: ${error.message}`));
        }
        
        return true;
    }
    
    async scenario6JSInteractiveDemo() {
        console.log(chalk.blue('\n🧪 Scenario 6: JavaScript Interactive Pinning Demo'));
        console.log(chalk.blue('=' .repeat(70)));
        
        // Load schema
        const schema = this.loadSampleSchema('mcp_tool');
        const privateKeyFile = join(this.keysDir, 'alice.example.com_private.pem');
        const publicKeyFile = join(this.keysDir, 'alice.example.com_public.pem');
        
        if (!existsSync(privateKeyFile) || !existsSync(publicKeyFile)) {
            console.log(chalk.yellow('⚠️  Demo environment not set up. Run Python demo with --setup first.'));
            return false;
        }
        
        const privateKeyPem = readFileSync(privateKeyFile, 'utf8');
        const publicKeyPem = readFileSync(publicKeyFile, 'utf8');
        
        // Sign schema
        console.log(chalk.green('📝 Signing schema...'));
        const signingWorkflow = new SchemaSigningWorkflow(privateKeyPem);
        const signature = signingWorkflow.signSchema(schema);
        
        // Create interactive verification workflow
        const verificationWorkflow = new SchemaVerificationWorkflow();
        
        // Mock discovery for demo
        verificationWorkflow.discovery.getPublicKeyPem = async (domain) => {
            console.log(chalk.gray(`🔍 Discovering public key for ${domain}...`));
            return publicKeyPem;
        };
        
        verificationWorkflow.discovery.getDeveloperInfo = async (domain) => {
            return { developer_name: "Alice Corp" };
        };
        
        verificationWorkflow.discovery.validateKeyNotRevoked = async (keyPem, domain) => {
            return true;
        };
        
        // Create interactive handler
        class DemoInteractiveHandler extends ConsoleInteractiveHandler {
            async promptPinKey(context) {
                console.log(chalk.cyan('\n🔐 Interactive Key Pinning Prompt:'));
                console.log(chalk.gray(`   Tool: ${context.toolId}`));
                console.log(chalk.gray(`   Domain: ${context.domain}`));
                console.log(chalk.gray(`   Developer: ${context.keyInfo.developerName}`));
                console.log(chalk.gray(`   Key fingerprint: ${context.keyInfo.fingerprint}`));
                
                const answer = await inquirer.prompt([{
                    type: 'confirm',
                    name: 'pin',
                    message: 'Do you want to pin this key for future use?',
                    default: true
                }]);
                
                return answer.pin;
            }
        }
        
        // Set up interactive pinning
        const interactiveHandler = new DemoInteractiveHandler();
        const interactivePinning = new InteractivePinningManager(interactiveHandler);
        
        // Override pinning behavior for demo
        const originalPinKey = verificationWorkflow.pinning.pinKey;
        verificationWorkflow.pinning.pinKey = (toolId, publicKeyPem, domain, developerName) => {
            console.log(chalk.green(`✅ Key pinned for ${toolId}`));
            return originalPinKey.call(verificationWorkflow.pinning, toolId, publicKeyPem, domain, developerName);
        };
        
        // Verify with interactive prompts
        console.log(chalk.blue('🔍 Starting interactive verification...'));
        
        try {
            const result = await verificationWorkflow.verifySchema(
                schema,
                signature,
                'alice.example.com/calculate_sum',
                'alice.example.com',
                false  // Don't auto-pin, force interactive
            );
            
            console.log(chalk.green('✅ Interactive verification completed!'));
            console.log(chalk.gray(`   Valid: ${result.valid}`));
            console.log(chalk.gray(`   Pinned: ${result.pinned}`));
            console.log(chalk.gray(`   First use: ${result.first_use}`));
            
        } catch (error) {
            console.log(chalk.red(`❌ Interactive verification failed: ${error.message}`));
        }
        
        return true;
    }
    
    async scenario7CrossLanguageCompatibility() {
        console.log(chalk.blue('\n🧪 Scenario 7: Cross-Language Compatibility Test'));
        console.log(chalk.blue('=' .repeat(70)));
        
        const schemas = ['mcp_tool', 'api_endpoint', 'complex_nested'];
        const results = [];
        
        for (const schemaName of schemas) {
            console.log(chalk.yellow(`\n📋 Testing ${schemaName}...`));
            
            const schema = this.loadSampleSchema(schemaName);
            const privateKeyFile = join(this.keysDir, 'alice.example.com_private.pem');
            const publicKeyFile = join(this.keysDir, 'alice.example.com_public.pem');
            
            if (!existsSync(privateKeyFile) || !existsSync(publicKeyFile)) {
                console.log(chalk.yellow('⚠️  Keys not found, skipping...'));
                continue;
            }
            
            const privateKeyPem = readFileSync(privateKeyFile, 'utf8');
            const publicKeyPem = readFileSync(publicKeyFile, 'utf8');
            
            // Sign with JavaScript
            const signingWorkflow = new SchemaSigningWorkflow(privateKeyPem);
            const jsSignature = signingWorkflow.signSchema(schema);
            
            // Verify with JavaScript
            const verificationWorkflow = new SchemaVerificationWorkflow();
            verificationWorkflow.discovery.getPublicKeyPem = async () => publicKeyPem;
            verificationWorkflow.discovery.validateKeyNotRevoked = async () => true;
            
            const jsResult = await verificationWorkflow.verifySchema(
                schema,
                jsSignature,
                `alice.example.com/${schemaName}`,
                'alice.example.com',
                true
            );
            
            // Test with Python verification
            const signedSchema = {
                schema: schema,
                signature: jsSignature,
                signed_at: new Date().toISOString(),
                metadata: {
                    developer: "Alice Corp",
                    domain: "alice.example.com",
                    tool_id: `alice.example.com/${schemaName}`
                }
            };
            
            const tempFile = join(this.signedSchemasDir, `temp_${schemaName}.json`);
            writeFileSync(tempFile, JSON.stringify(signedSchema, null, 2));
            
            let pythonResult = null;
            try {
                pythonResult = await this.runPythonVerification(tempFile);
            } catch (error) {
                pythonResult = { success: false, error: error.message };
            }
            
            const testResult = {
                schema: schemaName,
                js_sign_js_verify: jsResult.valid,
                js_sign_python_verify: pythonResult.success ? pythonResult.data.valid : false,
                error: pythonResult.success ? null : pythonResult.error
            };
            
            results.push(testResult);
            
            console.log(chalk.gray(`   JS → JS: ${testResult.js_sign_js_verify ? '✅' : '❌'}`));
            console.log(chalk.gray(`   JS → Python: ${testResult.js_sign_python_verify ? '✅' : '❌'}`));
            if (testResult.error) {
                console.log(chalk.red(`   Error: ${testResult.error}`));
            }
        }
        
        // Save compatibility results
        const resultsFile = join(this.verificationResultsDir, 'compatibility_results.json');
        writeFileSync(resultsFile, JSON.stringify({
            timestamp: new Date().toISOString(),
            results: results
        }, null, 2));
        
        console.log(chalk.green(`\n✅ Compatibility test completed! Results saved to ${resultsFile}`));
        
        return true;
    }
    
    async runPythonVerification(signedSchemaFile) {
        return new Promise((resolve, reject) => {
            const pythonScript = `
import sys
import json
sys.path.insert(0, '../python')
from schemapin.utils import SchemaVerificationWorkflow

# Load signed schema
with open('${signedSchemaFile}', 'r') as f:
    signed_data = json.load(f)

# Mock verification workflow
workflow = SchemaVerificationWorkflow()

# Mock discovery
with open('${join(this.keysDir, 'bob.example.com_public.pem')}', 'r') as f:
    public_key_pem = f.read()

workflow.discovery.get_public_key_pem = lambda domain: public_key_pem
workflow.discovery.get_developer_info = lambda domain: {"developer_name": "Bob Industries"}
workflow.discovery.validate_key_not_revoked = lambda key_pem, domain: True

# Verify
result = workflow.verify_schema(
    signed_data['schema'],
    signed_data['signature'],
    signed_data['metadata']['tool_id'],
    signed_data['metadata']['domain'],
    auto_pin=True
)

print(json.dumps(result))
`;
            
            const python = spawn('python3', ['-c', pythonScript], {
                cwd: this.baseDir,
                stdio: ['pipe', 'pipe', 'pipe']
            });
            
            let stdout = '';
            let stderr = '';
            
            python.stdout.on('data', (data) => {
                stdout += data.toString();
            });
            
            python.stderr.on('data', (data) => {
                stderr += data.toString();
            });
            
            python.on('close', (code) => {
                if (code === 0) {
                    try {
                        const result = JSON.parse(stdout.trim());
                        resolve({ success: true, data: result });
                    } catch (error) {
                        resolve({ success: false, error: `Failed to parse Python output: ${stdout}` });
                    }
                } else {
                    resolve({ success: false, error: stderr || `Python process exited with code ${code}` });
                }
            });
            
            python.on('error', (error) => {
                reject(error);
            });
        });
    }
    
    async interactiveMode() {
        console.log(chalk.blue('\n🧷 SchemaPin JavaScript Demo - Interactive Mode'));
        console.log(chalk.blue('=' .repeat(50)));
        
        while (true) {
            const { scenario } = await inquirer.prompt([{
                type: 'list',
                name: 'scenario',
                message: 'Select a scenario to run:',
                choices: [
                    { name: '2. JavaScript Signs → Python Verifies (Interactive)', value: 2 },
                    { name: '6. JavaScript Interactive Pinning Demo', value: 6 },
                    { name: '7. Cross-Language Compatibility Test', value: 7 },
                    { name: 'Exit', value: 0 }
                ]
            }]);
            
            if (scenario === 0) {
                console.log(chalk.green('\n👋 Goodbye!'));
                break;
            }
            
            try {
                switch (scenario) {
                    case 2:
                        await this.scenario2JSSignsPythonVerifies();
                        break;
                    case 6:
                        await this.scenario6JSInteractiveDemo();
                        break;
                    case 7:
                        await this.scenario7CrossLanguageCompatibility();
                        break;
                }
            } catch (error) {
                console.log(chalk.red(`❌ Error: ${error.message}`));
            }
            
            console.log('\n' + '─'.repeat(50));
        }
    }
}

async function main() {
    const args = process.argv.slice(2);
    const demo = new JSDemo();
    
    if (args.includes('--scenario')) {
        const scenarioIndex = args.indexOf('--scenario');
        const scenarioNum = parseInt(args[scenarioIndex + 1]);
        
        switch (scenarioNum) {
            case 2:
                await demo.scenario2JSSignsPythonVerifies();
                break;
            case 6:
                await demo.scenario6JSInteractiveDemo();
                break;
            case 7:
                await demo.scenario7CrossLanguageCompatibility();
                break;
            default:
                console.log(chalk.red(`❌ Invalid scenario: ${scenarioNum}`));
                console.log(chalk.yellow('Available scenarios: 2, 6, 7'));
        }
    } else if (args.includes('--interactive')) {
        await demo.interactiveMode();
    } else {
        console.log(chalk.blue('🧷 SchemaPin JavaScript Demo'));
        console.log(chalk.blue('=' .repeat(30)));
        console.log('\nUsage:');
        console.log('  node demo_scenario.js --scenario <number>');
        console.log('  node demo_scenario.js --interactive');
        console.log('\nAvailable scenarios:');
        console.log('  2. JavaScript Signs → Python Verifies (Interactive)');
        console.log('  6. JavaScript Interactive Pinning Demo');
        console.log('  7. Cross-Language Compatibility Test');
    }
}

if (import.meta.url === `file://${process.argv[1]}`) {
    main().catch(error => {
        console.error(chalk.red('Fatal error:'), error);
        process.exit(1);
    });
}