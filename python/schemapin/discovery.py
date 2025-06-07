"""Public key discovery via .well-known URIs per RFC 8615."""

import json
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests

from .crypto import KeyManager


class PublicKeyDiscovery:
    """Handles public key discovery from .well-known endpoints."""

    @staticmethod
    def construct_well_known_url(domain: str) -> str:
        """
        Construct .well-known URI for SchemaPin public key discovery.

        Args:
            domain: Tool provider domain

        Returns:
            Full .well-known URI
        """
        if not domain.startswith(('http://', 'https://')):
            domain = f"https://{domain}"
        return urljoin(domain, '/.well-known/schemapin.json')

    @staticmethod
    def validate_well_known_response(response_data: Dict[str, Any]) -> bool:
        """
        Validate .well-known response structure.

        Args:
            response_data: Parsed JSON response

        Returns:
            True if response is valid, False otherwise
        """
        required_fields = ['schema_version', 'public_key_pem']
        return all(field in response_data for field in required_fields)

    @classmethod
    def fetch_well_known(cls, domain: str, timeout: int = 10) -> Optional[Dict[str, Any]]:
        """
        Fetch and validate .well-known/schemapin.json from domain.

        Args:
            domain: Tool provider domain
            timeout: Request timeout in seconds

        Returns:
            Parsed response data if valid, None otherwise
        """
        try:
            url = cls.construct_well_known_url(domain)
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()

            data = response.json()
            if cls.validate_well_known_response(data):
                return data
            return None

        except (requests.RequestException, json.JSONDecodeError, ValueError):
            return None

    @classmethod
    def get_public_key_pem(cls, domain: str, timeout: int = 10) -> Optional[str]:
        """
        Get public key PEM from domain's .well-known endpoint.

        Args:
            domain: Tool provider domain
            timeout: Request timeout in seconds

        Returns:
            PEM-encoded public key if found, None otherwise
        """
        well_known_data = cls.fetch_well_known(domain, timeout)
        if well_known_data:
            return well_known_data.get('public_key_pem')
        return None

    @classmethod
    def check_key_revocation(cls, public_key_pem: str, revoked_keys: List[str]) -> bool:
        """
        Check if a public key is in the revocation list.

        Args:
            public_key_pem: PEM-encoded public key string
            revoked_keys: List of revoked key fingerprints

        Returns:
            True if key is revoked, False otherwise
        """
        if not revoked_keys:
            return False

        try:
            fingerprint = KeyManager.calculate_key_fingerprint_from_pem(public_key_pem)
            return fingerprint in revoked_keys
        except Exception:
            # If we can't calculate fingerprint, assume not revoked
            return False

    @classmethod
    def get_revoked_keys(cls, domain: str, timeout: int = 10) -> Optional[List[str]]:
        """
        Get revoked keys list from domain's .well-known endpoint.

        Args:
            domain: Tool provider domain
            timeout: Request timeout in seconds

        Returns:
            List of revoked key fingerprints if available, None otherwise
        """
        well_known_data = cls.fetch_well_known(domain, timeout)
        if well_known_data:
            return well_known_data.get('revoked_keys', [])
        return None

    @classmethod
    def validate_key_not_revoked(cls, public_key_pem: str, domain: str, timeout: int = 10) -> bool:
        """
        Validate that a public key is not revoked.

        Args:
            public_key_pem: PEM-encoded public key string
            domain: Tool provider domain
            timeout: Request timeout in seconds

        Returns:
            True if key is not revoked, False if revoked or error
        """
        revoked_keys = cls.get_revoked_keys(domain, timeout)
        if revoked_keys is None:
            # If we can't fetch revocation list, assume not revoked
            return True

        return not cls.check_key_revocation(public_key_pem, revoked_keys)

    @classmethod
    def get_developer_info(cls, domain: str, timeout: int = 10) -> Optional[Dict[str, str]]:
        """
        Get developer information from .well-known endpoint.

        Args:
            domain: Tool provider domain
            timeout: Request timeout in seconds

        Returns:
            Dictionary with developer info if available, None otherwise
        """
        well_known_data = cls.fetch_well_known(domain, timeout)
        if well_known_data:
            return {
                'developer_name': well_known_data.get('developer_name', 'Unknown'),
                'schema_version': well_known_data.get('schema_version', '1.0'),
                'contact': well_known_data.get('contact', ''),
            }
        return None
