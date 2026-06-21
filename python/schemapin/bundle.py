"""Trust bundles for offline/air-gapped SchemaPin verification.

v1.4 adds optional distribution fields (``bundle_authority``, ``signed_at``,
``expires_at``, ``signature``) so bundles can be signed by a bundle authority
and safely exchanged between agents over A2A. See
:mod:`schemapin.bundle_distribution` for the sign / verify / merge operations.
"""

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .revocation import RevocationDocument


@dataclass
class BundleAuthority:
    """(v1.4) Identifies and carries the public key of the authority that
    signed a trust bundle. TOFU-pinned by ``kid`` on first use (see
    :func:`schemapin.bundle_distribution.verify_trust_bundle`).
    """

    kid: str
    public_key_pem: str

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {"kid": self.kid, "public_key_pem": self.public_key_pem}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BundleAuthority":
        """Deserialize from dictionary."""
        return cls(kid=data["kid"], public_key_pem=data["public_key_pem"])


@dataclass
class SchemaPinTrustBundle:
    """A bundle of discovery documents and revocations for offline use."""

    schemapin_bundle_version: str
    created_at: str
    documents: List[Dict[str, Any]] = field(default_factory=list)
    revocations: List[RevocationDocument] = field(default_factory=list)
    # (v1.4) Optional bundle-distribution fields. Present on signed bundles;
    # omitted entirely (not serialized) on unsigned bundles.
    bundle_authority: Optional[BundleAuthority] = None
    signed_at: Optional[str] = None
    expires_at: Optional[str] = None
    signature: Optional[str] = None

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
        """Serialize to dictionary with flattened BundledDiscovery format.

        Optional v1.4 distribution fields are only included when present, so
        unsigned bundles serialize identically to the pre-v1.4 wire format.
        """
        d: Dict[str, Any] = {
            "schemapin_bundle_version": self.schemapin_bundle_version,
            "created_at": self.created_at,
            "documents": self.documents,
            "revocations": [r.to_dict() for r in self.revocations],
        }
        if self.bundle_authority is not None:
            d["bundle_authority"] = self.bundle_authority.to_dict()
        if self.signed_at is not None:
            d["signed_at"] = self.signed_at
        if self.expires_at is not None:
            d["expires_at"] = self.expires_at
        if self.signature is not None:
            d["signature"] = self.signature
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SchemaPinTrustBundle":
        """Deserialize from dictionary."""
        ba = data.get("bundle_authority")
        return cls(
            schemapin_bundle_version=data["schemapin_bundle_version"],
            created_at=data["created_at"],
            documents=data.get("documents", []),
            revocations=[
                RevocationDocument.from_dict(r)
                for r in data.get("revocations", [])
            ],
            bundle_authority=BundleAuthority.from_dict(ba) if ba else None,
            signed_at=data.get("signed_at"),
            expires_at=data.get("expires_at"),
            signature=data.get("signature"),
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
