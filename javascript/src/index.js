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
    parseTrustBundle,
    // v1.4: A2A trust-bundle distribution
    BUNDLE_VERSION_SIGNED,
    BUNDLE_AUTHORITY_PIN_DOMAIN,
    signTrustBundle,
    verifyTrustBundle,
    mergeTrustBundles,
    buildTrustBundleRequest,
    buildTrustBundleResponse,
    parseTrustBundleResponse
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
    verifySchemaWithResolver,
    applyExpirationCheck,
    // v1.4 alpha.3
    CANONICALIZATION_V1,
    checkCanonicalization,
    A2A_MAX_DELEGATION_DEPTH,
    verifySchemaForA2A
} from './verification.js';

// v1.4 alpha.3: A2A verification context
export {
    A2aVerificationContext,
    a2aIsUnrestricted,
    a2aAllows,
    a2aIntersect
} from './a2a.js';

// v1.3.0 new module
export {
    SIGNATURE_FILENAME,
    canonicalizeSkill,
    parseSkillName,
    loadSignature,
    signSkill,
    signSkillWithOptions,
    verifySkillOffline,
    verifySkillOfflineWithDns,
    verifySkillWithResolver,
    detectTamperedFiles
} from './skill.js';

// v1.4.0-alpha.1: DNS TXT cross-verification
export {
    parseTxtRecord,
    verifyDnsMatch,
    txtRecordName,
    fetchDnsTxt
} from './dns.js';

export const version = '1.4.0-alpha.1';
