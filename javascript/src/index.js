/**
 * SchemaPin: Cryptographic schema integrity verification for AI tools.
 */

export { SchemaPinCore } from './core.js';
export { KeyManager, SignatureManager } from './crypto.js';
export { PublicKeyDiscovery } from './discovery.js';
export { KeyPinning } from './pinning.js';
export { 
    SchemaSigningWorkflow, 
    SchemaVerificationWorkflow, 
    createWellKnownResponse 
} from './utils.js';

export const version = '1.0.0';