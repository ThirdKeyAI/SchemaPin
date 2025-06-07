/**
 * SchemaPin: Cryptographic schema integrity verification for AI tools.
 */

export { SchemaPinCore } from './core.js';
export { KeyManager, SignatureManager } from './crypto.js';
export { PublicKeyDiscovery } from './discovery.js';
export { KeyPinning, PinningMode, PinningPolicy } from './pinning.js';
export {
    SchemaSigningWorkflow,
    SchemaVerificationWorkflow,
    createWellKnownResponse
} from './utils.js';
export {
    InteractivePinningManager,
    ConsoleInteractiveHandler,
    CallbackInteractiveHandler,
    PromptType,
    UserDecision,
    KeyInfo,
    PromptContext,
    InteractiveHandler
} from './interactive.js';

export const version = '1.1.0';