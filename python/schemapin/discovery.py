"""Public key discovery via .well-known URIs per RFC 8615.

All network access goes through :mod:`schemapin.transport`: ``https://`` only,
no redirects, capped bodies, timeouts. Domains are validated with
:func:`schemapin.domain.validate_domain` before a URL is built.
"""

from typing import Any, Dict, List, Optional

from .crypto import KeyManager
from .domain import InvalidDomainError, validate_domain
from .revocation import (
    RevocationFetchError,
    check_revocation,
    fetch_revocation_document,
)
from .transport import DEFAULT_TIMEOUT, TransportError, fetch_json


class PublicKeyDiscovery:
    """Handles public key discovery from .well-known endpoints."""

    @staticmethod
    def construct_well_known_url(domain: str) -> str:
        """
        Construct the ``.well-known`` URI for SchemaPin public key discovery.

        ``domain`` must be a bare hostname (an ``https://`` prefix is
        tolerated and stripped). ``http://`` is refused: the spec requires
        HTTPS and a plaintext first fetch would let a network attacker pin
        their own key.

        Raises:
            ValueError: for ``http://`` prefixes or an invalid domain.
        """
        if domain.startswith("http://"):
            raise ValueError("SchemaPin discovery requires https; http:// is not permitted")
        if domain.startswith("https://"):
            domain = domain[len("https://"):].rstrip("/")
        try:
            domain = validate_domain(domain)
        except InvalidDomainError as e:
            raise ValueError(str(e)) from e
        return f"https://{domain}/.well-known/schemapin.json"

    @staticmethod
    def validate_well_known_response(response_data: Dict[str, Any]) -> bool:
        """
        Validate .well-known response structure.

        Args:
            response_data: Parsed JSON response

        Returns:
            True if response is valid, False otherwise
        """
        if not isinstance(response_data, dict):
            return False
        required_fields = ['schema_version', 'public_key_pem']
        return all(field in response_data for field in required_fields)

    @classmethod
    def fetch_well_known(cls, domain: str, timeout: int = DEFAULT_TIMEOUT) -> Optional[Dict[str, Any]]:
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
            data = fetch_json(url, timeout=timeout)
        except (TransportError, ValueError):
            return None
        if cls.validate_well_known_response(data):
            return data
        return None

    @classmethod
    def get_public_key_pem(cls, domain: str, timeout: int = DEFAULT_TIMEOUT) -> Optional[str]:
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
            True if key is revoked (or cannot be fingerprinted), False otherwise
        """
        if not revoked_keys:
            return False

        try:
            fingerprint = KeyManager.calculate_key_fingerprint_from_pem(public_key_pem)
        except Exception:
            # A key that cannot be fingerprinted cannot be trusted either.
            return True
        return fingerprint in revoked_keys

    @classmethod
    def get_revoked_keys(cls, domain: str, timeout: int = DEFAULT_TIMEOUT) -> Optional[List[str]]:
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
    def validate_key_not_revoked(
        cls,
        public_key_pem: str,
        domain: str,
        timeout: int = DEFAULT_TIMEOUT,
        allow_unreachable: bool = False,
    ) -> bool:
        """
        Validate that a public key is not revoked (fail-closed).

        Consults both the inline ``revoked_keys`` list and, when the discovery
        document declares one, the standalone ``revocation_endpoint``. If
        either cannot be fetched the key is treated as **not validated** and
        ``False`` is returned, unless ``allow_unreachable=True``.

        Args:
            public_key_pem: PEM-encoded public key string
            domain: Tool provider domain
            timeout: Request timeout in seconds
            allow_unreachable: Treat fetch failures as "not revoked"

        Returns:
            True if the key is confirmed not revoked, False otherwise
        """
        well_known = cls.fetch_well_known(domain, timeout)
        if well_known is None:
            return allow_unreachable
        if cls.check_key_revocation(public_key_pem, well_known.get('revoked_keys', [])):
            return False
        endpoint = well_known.get('revocation_endpoint')
        if endpoint:
            try:
                doc = fetch_revocation_document(endpoint, timeout=timeout)
            except RevocationFetchError:
                return allow_unreachable
            try:
                fingerprint = KeyManager.calculate_key_fingerprint_from_pem(public_key_pem)
                check_revocation(doc, fingerprint)
            except ValueError:
                return False
        return True

    @classmethod
    def get_developer_info(cls, domain: str, timeout: int = DEFAULT_TIMEOUT) -> Optional[Dict[str, str]]:
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
