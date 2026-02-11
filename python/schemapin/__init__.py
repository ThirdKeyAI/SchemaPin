"""SchemaPin: Cryptographic schema integrity verification for AI tools."""

from .core import SchemaPinCore
from .crypto import KeyManager, SignatureManager
from .discovery import PublicKeyDiscovery
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
from .utils import (
    SchemaSigningWorkflow,
    SchemaVerificationWorkflow,
    create_well_known_response,
)

# v1.2.0 new modules
from .revocation import (
    RevocationDocument,
    RevocationReason,
    RevokedKey,
    build_revocation_document,
    add_revoked_key,
    check_revocation,
    check_revocation_combined,
    fetch_revocation_document,
)
from .bundle import (
    SchemaPinTrustBundle,
    create_bundled_discovery,
)
from .resolver import (
    SchemaResolver,
    WellKnownResolver,
    LocalFileResolver,
    TrustBundleResolver,
    ChainResolver,
)
from .verification import (
    ErrorCode,
    KeyPinStore,
    KeyPinningStatus,
    VerificationResult,
    verify_schema_offline,
    verify_schema_with_resolver,
)

__version__ = "1.2.0"
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
]
