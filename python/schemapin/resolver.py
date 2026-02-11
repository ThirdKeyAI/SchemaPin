"""Discovery resolver abstraction for SchemaPin."""

import json
import os
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from .bundle import SchemaPinTrustBundle
from .discovery import PublicKeyDiscovery
from .revocation import RevocationDocument, fetch_revocation_document


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
        """Fetch revocation from the discovery's revocation_endpoint."""
        endpoint = discovery.get("revocation_endpoint")
        if not endpoint:
            return None
        return fetch_revocation_document(endpoint, timeout=self._timeout)


class LocalFileResolver(SchemaResolver):
    """Resolves discovery from local JSON files."""

    def __init__(
        self, discovery_dir: str, revocation_dir: Optional[str] = None
    ):
        self._discovery_dir = discovery_dir
        self._revocation_dir = revocation_dir

    def resolve_discovery(self, domain: str) -> Optional[Dict[str, Any]]:
        """Read {domain}.json from the discovery directory."""
        path = os.path.join(self._discovery_dir, f"{domain}.json")
        try:
            with open(path) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return None

    def resolve_revocation(
        self, domain: str, discovery: Dict[str, Any]
    ) -> Optional[RevocationDocument]:
        """Read {domain}.revocations.json from the revocation directory."""
        if not self._revocation_dir:
            return None
        path = os.path.join(
            self._revocation_dir, f"{domain}.revocations.json"
        )
        try:
            with open(path) as f:
                data = json.load(f)
                return RevocationDocument.from_dict(data)
        except (OSError, json.JSONDecodeError):
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
    """Tries multiple resolvers in order, returning the first success."""

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
