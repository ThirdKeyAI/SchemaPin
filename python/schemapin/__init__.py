"""SchemaPin: Cryptographic schema integrity verification for AI tools."""

from .bundle import (
    SchemaPinTrustBundle,
    create_bundled_discovery,
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
    ErrorCode,
    KeyPinningStatus,
    KeyPinStore,
    VerificationResult,
    verify_schema_offline,
    verify_schema_with_resolver,
)

__version__ = "1.4.0a1"
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
]
