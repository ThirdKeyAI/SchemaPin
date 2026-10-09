"""Discovery resolver abstraction for SchemaPin."""

import json
import os
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from .bundle import SchemaPinTrustBundle
from .discovery import PublicKeyDiscovery
from .domain import InvalidDomainError, validate_domain
from .revocation import RevocationDocument, fetch_revocation_document


def _safe_domain_path(base_dir: str, domain: str, suffix: str) -> Optional[str]:
    """Join a validated domain-derived file name onto ``base_dir``.

    Returns ``None`` when the domain is invalid or the resolved path would
    escape ``base_dir`` (SP-16), so a hostile domain string can never select
    an arbitrary file.
    """
    try:
        normalized = validate_domain(domain)
    except InvalidDomainError:
        return None
    root = os.path.realpath(base_dir)
    path = os.path.realpath(os.path.join(root, f"{normalized}{suffix}"))
    if path != root and not path.startswith(root + os.sep):
        return None
    return path


class SchemaResolver(ABC):
    """Abstract base class for discovery resolution."""

    @abstractmethod
    def resolve_discovery(self, domain: str) -> Optional[Dict[str, Any]]:
        """Resolve a well-known discovery document for a domain.

        Returns:
            Well-known response dict, or None if not found.
        """

    @abstractmethod
    def resolve_revocation(
        self, domain: str, discovery: Dict[str, Any]
    ) -> Optional[RevocationDocument]:
        """Resolve a revocation document for a domain.

        Returns:
            RevocationDocument or None.
        """


class WellKnownResolver(SchemaResolver):
    """Resolves discovery via standard .well-known HTTPS endpoints."""

    def __init__(self, timeout: int = 10):
        self._timeout = timeout

    def resolve_discovery(self, domain: str) -> Optional[Dict[str, Any]]:
        """Fetch discovery from .well-known endpoint."""
        try:
            return PublicKeyDiscovery.fetch_well_known(
                domain, timeout=self._timeout
            )
        except Exception:
            return None

    def resolve_revocation(
        self, domain: str, discovery: Dict[str, Any]
    ) -> Optional[RevocationDocument]:
        """Fetch revocation from the discovery's revocation_endpoint.

        Raises:
            RevocationFetchError: when the endpoint is declared but cannot be
                fetched or parsed (callers fail closed).
        """
        endpoint = discovery.get("revocation_endpoint")
        if not endpoint:
            return None
        return fetch_revocation_document(endpoint, timeout=self._timeout)


class LocalFileResolver(SchemaResolver):
    """Resolves discovery from local JSON files.

    The domain is validated and the resolved path must stay inside the
    configured directory, so a hostile domain string cannot select an
    arbitrary file.
    """

    def __init__(
        self, discovery_dir: str, revocation_dir: Optional[str] = None
    ):
        self._discovery_dir = discovery_dir
        self._revocation_dir = revocation_dir

    def resolve_discovery(self, domain: str) -> Optional[Dict[str, Any]]:
        """Read {domain}.json from the discovery directory."""
        path = _safe_domain_path(self._discovery_dir, domain, ".json")
        if path is None:
            return None
        try:
            with open(path) as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return None
        return data if isinstance(data, dict) else None

    def resolve_revocation(
        self, domain: str, discovery: Dict[str, Any]
    ) -> Optional[RevocationDocument]:
        """Read {domain}.revocations.json from the revocation directory."""
        if not self._revocation_dir:
            return None
        path = _safe_domain_path(self._revocation_dir, domain, ".revocations.json")
        if path is None:
            return None
        try:
            with open(path) as f:
                data = json.load(f)
                return RevocationDocument.from_dict(data)
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            return None


class TrustBundleResolver(SchemaResolver):
    """Resolves discovery from an in-memory trust bundle."""

    def __init__(self, bundle: SchemaPinTrustBundle):
        self._bundle = bundle

    @classmethod
    def from_json(cls, json_str: str) -> "TrustBundleResolver":
        """Create resolver from a JSON trust bundle string."""
        bundle = SchemaPinTrustBundle.from_json(json_str)
        return cls(bundle)

    def resolve_discovery(self, domain: str) -> Optional[Dict[str, Any]]:
        """Look up discovery in the bundle."""
        return self._bundle.find_discovery(domain)

    def resolve_revocation(
        self, domain: str, discovery: Dict[str, Any]
    ) -> Optional[RevocationDocument]:
        """Look up revocation in the bundle."""
        return self._bundle.find_revocation(domain)


class ChainResolver(SchemaResolver):
    """Tries multiple resolvers in order, returning the first success.

    Precedence is positional: put the most trusted source first. A
    :class:`~schemapin.revocation.RevocationFetchError` raised by any member
    propagates (fail-closed) instead of being skipped.
    """

    def __init__(self, resolvers: List[SchemaResolver]):
        self._resolvers = resolvers

    def resolve_discovery(self, domain: str) -> Optional[Dict[str, Any]]:
        """Try each resolver in order."""
        for resolver in self._resolvers:
            result = resolver.resolve_discovery(domain)
            if result is not None:
                return result
        return None

    def resolve_revocation(
        self, domain: str, discovery: Dict[str, Any]
    ) -> Optional[RevocationDocument]:
        """Try each resolver in order."""
        for resolver in self._resolvers:
            result = resolver.resolve_revocation(domain, discovery)
            if result is not None:
                return result
        return None
