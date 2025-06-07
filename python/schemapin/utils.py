"""Utility functions for SchemaPin operations."""

from typing import Any, Dict, List, Optional

from .core import SchemaPinCore
from .crypto import KeyManager, SignatureManager
from .discovery import PublicKeyDiscovery
from .pinning import KeyPinning


class SchemaSigningWorkflow:
    """High-level workflow for tool developers to sign schemas."""

    def __init__(self, private_key_pem: str):
        """
        Initialize signing workflow with private key.

        Args:
            private_key_pem: PEM-encoded private key
        """
        self.private_key = KeyManager.load_private_key_pem(private_key_pem)

    def sign_schema(self, schema: Dict[str, Any]) -> str:
        """
        Sign a tool schema and return Base64 signature.

        Args:
            schema: Tool schema dictionary

        Returns:
            Base64-encoded signature
        """
        schema_hash = SchemaPinCore.canonicalize_and_hash(schema)
        return SignatureManager.sign_schema_hash(schema_hash, self.private_key)


class SchemaVerificationWorkflow:
    """High-level workflow for clients to verify schemas."""

    def __init__(self, pinning_db_path: Optional[str] = None):
        """
        Initialize verification workflow.

        Args:
            pinning_db_path: Optional path to key pinning database
        """
        self.pinning = KeyPinning(pinning_db_path)
        self.discovery = PublicKeyDiscovery()

    def verify_schema(
        self,
        schema: Dict[str, Any],
        signature_b64: str,
        tool_id: str,
        domain: str,
        auto_pin: bool = False
    ) -> Dict[str, Any]:
        """
        Verify schema signature with key pinning support.

        Args:
            schema: Tool schema dictionary
            signature_b64: Base64-encoded signature
            tool_id: Unique tool identifier
            domain: Tool provider domain
            auto_pin: Whether to auto-pin keys on first use

        Returns:
            Dictionary with verification result and metadata
        """
        result = {
            'valid': False,
            'pinned': False,
            'first_use': False,
            'error': None,
            'developer_info': None
        }

        try:
            # Check for pinned key
            pinned_key_pem = self.pinning.get_pinned_key(tool_id)

            if pinned_key_pem:
                # Use pinned key, but check if it's been revoked
                if not self.discovery.validate_key_not_revoked(pinned_key_pem, domain):
                    result['error'] = 'Pinned public key has been revoked'
                    return result

                public_key = KeyManager.load_public_key_pem(pinned_key_pem)
                result['pinned'] = True
            else:
                # First use - discover key
                public_key_pem = self.discovery.get_public_key_pem(domain)
                if not public_key_pem:
                    result['error'] = 'Could not discover public key'
                    return result

                # Check if key is revoked
                if not self.discovery.validate_key_not_revoked(public_key_pem, domain):
                    result['error'] = 'Public key has been revoked'
                    return result

                public_key = KeyManager.load_public_key_pem(public_key_pem)
                result['first_use'] = True
                result['developer_info'] = self.discovery.get_developer_info(domain)

                # Auto-pin if requested
                if auto_pin:
                    developer_name = None
                    if result['developer_info']:
                        developer_name = result['developer_info']['developer_name']

                    self.pinning.pin_key(tool_id, public_key_pem, domain, developer_name)
                    result['pinned'] = True

            # Verify signature
            schema_hash = SchemaPinCore.canonicalize_and_hash(schema)
            result['valid'] = SignatureManager.verify_schema_signature(
                schema_hash, signature_b64, public_key
            )

            # Update verification timestamp if valid and pinned
            if result['valid'] and result['pinned']:
                self.pinning.update_last_verified(tool_id)

        except Exception as e:
            result['error'] = str(e)

        return result

    def pin_key_for_tool(
        self,
        tool_id: str,
        domain: str,
        developer_name: Optional[str] = None
    ) -> bool:
        """
        Manually pin key for a tool.

        Args:
            tool_id: Unique tool identifier
            domain: Tool provider domain
            developer_name: Optional developer name

        Returns:
            True if key was pinned successfully, False otherwise
        """
        public_key_pem = self.discovery.get_public_key_pem(domain)
        if public_key_pem:
            return self.pinning.pin_key(tool_id, public_key_pem, domain, developer_name)
        return False


def create_well_known_response(
    public_key_pem: str,
    developer_name: str,
    contact: Optional[str] = None,
    revoked_keys: Optional[List[str]] = None,
    schema_version: str = "1.1"
) -> Dict[str, Any]:
    """
    Create .well-known/schemapin.json response structure.

    Args:
        public_key_pem: PEM-encoded public key
        developer_name: Developer or organization name
        contact: Optional contact information
        revoked_keys: Optional list of revoked key fingerprints
        schema_version: Schema version (default: "1.1")

    Returns:
        Dictionary suitable for .well-known response
    """
    response = {
        'schema_version': schema_version,
        'developer_name': developer_name,
        'public_key_pem': public_key_pem
    }

    if contact:
        response['contact'] = contact

    if revoked_keys:
        response['revoked_keys'] = revoked_keys

    return response
