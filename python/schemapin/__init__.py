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

__version__ = "1.1.0"
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
    "InteractiveHandler"
]
