"""Trust bundles for offline/air-gapped SchemaPin verification."""

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .revocation import RevocationDocument


@dataclass
class SchemaPinTrustBundle:
    """A bundle of discovery documents and revocations for offline use."""

    schemapin_bundle_version: str
    created_at: str
    documents: List[Dict[str, Any]] = field(default_factory=list)
    revocations: List[RevocationDocument] = field(default_factory=list)

    def find_discovery(self, domain: str) -> Optional[Dict[str, Any]]:
        """Find a discovery document for a domain.

        Returns the well-known fields (without the 'domain' key) or None.
        """
        for doc in self.documents:
            if doc.get("domain") == domain:
                result = {k: v for k, v in doc.items() if k != "domain"}
                return result
        return None

    def find_revocation(self, domain: str) -> Optional[RevocationDocument]:
        """Find a revocation document for a domain."""
        for rev in self.revocations:
            if rev.domain == domain:
                return rev
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary with flattened BundledDiscovery format."""
        return {
            "schemapin_bundle_version": self.schemapin_bundle_version,
            "created_at": self.created_at,
            "documents": self.documents,
            "revocations": [r.to_dict() for r in self.revocations],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SchemaPinTrustBundle":
        """Deserialize from dictionary."""
        return cls(
            schemapin_bundle_version=data["schemapin_bundle_version"],
            created_at=data["created_at"],
            documents=data.get("documents", []),
            revocations=[
                RevocationDocument.from_dict(r)
                for r in data.get("revocations", [])
            ],
        )

    @classmethod
    def from_json(cls, json_str: str) -> "SchemaPinTrustBundle":
        """Deserialize from JSON string."""
        return cls.from_dict(json.loads(json_str))


def create_bundled_discovery(
    domain: str, well_known: Dict[str, Any]
) -> Dict[str, Any]:
    """Create a flattened BundledDiscovery entry.

    Merges domain with well-known fields at the same level.
    """
    entry = {"domain": domain}
    entry.update(well_known)
    return entry
