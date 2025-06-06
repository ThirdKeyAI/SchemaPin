"""SchemaPin: Cryptographic schema integrity verification for AI tools."""

from .core import SchemaPinCore
from .crypto import KeyManager, SignatureManager
from .discovery import PublicKeyDiscovery
from .pinning import KeyPinning

__version__ = "1.0.0"
__all__ = [
    "SchemaPinCore",
    "KeyManager", 
    "SignatureManager",
    "PublicKeyDiscovery",
    "KeyPinning",
]