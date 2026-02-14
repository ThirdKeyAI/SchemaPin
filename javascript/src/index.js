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

// v1.2.0 new modules
export {
    RevocationReason,
    buildRevocationDocument,
    addRevokedKey,
    checkRevocation,
    checkRevocationCombined,
    fetchRevocationDocument
} from './revocation.js';
export {
    createTrustBundle,
    createBundledDiscovery,
    findDiscovery,
    findRevocation,
    parseTrustBundle
} from './bundle.js';
export {
    SchemaResolver,
    WellKnownResolver,
    LocalFileResolver,
    TrustBundleResolver,
    ChainResolver
} from './resolver.js';
export {
    ErrorCode,
    KeyPinStore,
    verifySchemaOffline,
    verifySchemaWithResolver
} from './verification.js';

// v1.3.0 new module
export {
    SIGNATURE_FILENAME,
    canonicalizeSkill,
    parseSkillName,
    loadSignature,
    signSkill,
    verifySkillOffline,
    verifySkillWithResolver,
    detectTamperedFiles
} from './skill.js';

export const version = '1.3.0';
