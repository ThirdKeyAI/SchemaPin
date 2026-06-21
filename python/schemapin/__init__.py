"""SchemaPin: Cryptographic schema integrity verification for AI tools."""

from .a2a import (
    A2aVerificationContext,
)
from .a2a import (
    allows as a2a_allows,
)
from .a2a import (
    intersect as a2a_intersect,
)
from .a2a import (
    is_unrestricted as a2a_is_unrestricted,
)
from .bundle import (
    BundleAuthority,
    SchemaPinTrustBundle,
    create_bundled_discovery,
)
from .bundle_distribution import (
    BUNDLE_AUTHORITY_PIN_DOMAIN,
    BUNDLE_VERSION_SIGNED,
    BundleVerificationError,
    build_trust_bundle_request,
    build_trust_bundle_response,
    merge_trust_bundles,
    parse_trust_bundle_response,
    sign_trust_bundle,
    verify_trust_bundle,
)
from .core import SchemaPinCore
from .crypto import KeyManager, SignatureManager
from .discovery import PublicKeyDiscovery
from .dns import (
    DnsTxtRecord,
    fetch_dns_txt,
    parse_txt_record,
    txt_record_name,
    verify_dns_match,
)
from .interactive import (
    CallbackInteractiveHandler,
    ConsoleInteractiveHandler,
    InteractiveHandler,
    InteractivePinningManager,
    KeyInfo,
    PromptContext,
    PromptType,
    UserDecision,
)
from .pinning import KeyPinning, PinningMode, PinningPolicy
from .resolver import (
    ChainResolver,
    LocalFileResolver,
    SchemaResolver,
    TrustBundleResolver,
    WellKnownResolver,
)
from .revocation import (
    RevocationDocument,
    RevocationReason,
    RevokedKey,
    add_revoked_key,
    build_revocation_document,
    check_revocation,
    check_revocation_combined,
    fetch_revocation_document,
)
from .skill import (
    SCHEMAPIN_VERSION_V1_4,
    SIGNATURE_FILENAME,
    SignOptions,
    SkillSigner,
)
from .utils import (
    SchemaSigningWorkflow,
    SchemaVerificationWorkflow,
    create_well_known_response,
)
from .verification import (
    A2A_MAX_DELEGATION_DEPTH,
    CANONICALIZATION_V1,
    ErrorCode,
    KeyPinningStatus,
    KeyPinStore,
    VerificationResult,
    check_canonicalization,
    verify_schema_for_a2a,
    verify_schema_offline,
    verify_schema_with_resolver,
)

__version__ = "1.4.0a4"
__all__ = [
    "SchemaPinCore",
    "KeyManager",
    "SignatureManager",
    "PublicKeyDiscovery",
    "KeyPinning",
    "PinningMode",
    "PinningPolicy",
    "SchemaSigningWorkflow",
    "SchemaVerificationWorkflow",
    "create_well_known_response",
    "InteractivePinningManager",
    "ConsoleInteractiveHandler",
    "CallbackInteractiveHandler",
    "PromptType",
    "UserDecision",
    "KeyInfo",
    "PromptContext",
    "InteractiveHandler",
    # v1.2.0
    "RevocationDocument",
    "RevocationReason",
    "RevokedKey",
    "build_revocation_document",
    "add_revoked_key",
    "check_revocation",
    "check_revocation_combined",
    "fetch_revocation_document",
    "SchemaPinTrustBundle",
    "create_bundled_discovery",
    "SchemaResolver",
    "WellKnownResolver",
    "LocalFileResolver",
    "TrustBundleResolver",
    "ChainResolver",
    "ErrorCode",
    "KeyPinStore",
    "KeyPinningStatus",
    "VerificationResult",
    "verify_schema_offline",
    "verify_schema_with_resolver",
    # v1.3.0
    "SkillSigner",
    "SIGNATURE_FILENAME",
    # v1.4.0
    "SCHEMAPIN_VERSION_V1_4",
    "SignOptions",
    "DnsTxtRecord",
    "parse_txt_record",
    "verify_dns_match",
    "txt_record_name",
    "fetch_dns_txt",
    # v1.4 alpha.3
    "CANONICALIZATION_V1",
    "check_canonicalization",
    "A2A_MAX_DELEGATION_DEPTH",
    "verify_schema_for_a2a",
    "A2aVerificationContext",
    "a2a_allows",
    "a2a_intersect",
    "a2a_is_unrestricted",
    # v1.4 — A2A trust-bundle distribution
    "BundleAuthority",
    "BundleVerificationError",
    "BUNDLE_VERSION_SIGNED",
    "BUNDLE_AUTHORITY_PIN_DOMAIN",
    "sign_trust_bundle",
    "verify_trust_bundle",
    "merge_trust_bundles",
    "build_trust_bundle_request",
    "build_trust_bundle_response",
    "parse_trust_bundle_response",
]
