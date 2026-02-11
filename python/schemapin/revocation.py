"""Standalone revocation documents for SchemaPin v1.2."""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import requests


class RevocationReason(Enum):
    """Reason for key revocation."""

    KEY_COMPROMISE = "key_compromise"
    SUPERSEDED = "superseded"
    CESSATION_OF_OPERATION = "cessation_of_operation"
    PRIVILEGE_WITHDRAWN = "privilege_withdrawn"


@dataclass
class RevokedKey:
    """A single revoked key entry."""

    fingerprint: str
    revoked_at: str
    reason: RevocationReason

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "fingerprint": self.fingerprint,
            "revoked_at": self.revoked_at,
            "reason": self.reason.value,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RevokedKey":
        """Deserialize from dictionary."""
        return cls(
            fingerprint=data["fingerprint"],
            revoked_at=data["revoked_at"],
            reason=RevocationReason(data["reason"]),
        )


@dataclass
class RevocationDocument:
    """Standalone revocation document."""

    schemapin_version: str
    domain: str
    updated_at: str
    revoked_keys: List[RevokedKey] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "schemapin_version": self.schemapin_version,
            "domain": self.domain,
            "updated_at": self.updated_at,
            "revoked_keys": [k.to_dict() for k in self.revoked_keys],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RevocationDocument":
        """Deserialize from dictionary."""
        return cls(
            schemapin_version=data["schemapin_version"],
            domain=data["domain"],
            updated_at=data["updated_at"],
            revoked_keys=[
                RevokedKey.from_dict(k) for k in data.get("revoked_keys", [])
            ],
        )


def build_revocation_document(domain: str) -> RevocationDocument:
    """Create an empty revocation document for a domain."""
    now = datetime.now(timezone.utc).isoformat()
    return RevocationDocument(
        schemapin_version="1.2",
        domain=domain,
        updated_at=now,
        revoked_keys=[],
    )


def add_revoked_key(
    doc: RevocationDocument,
    fingerprint: str,
    reason: RevocationReason,
) -> None:
    """Add a revoked key entry to the document."""
    now = datetime.now(timezone.utc).isoformat()
    doc.revoked_keys.append(
        RevokedKey(fingerprint=fingerprint, revoked_at=now, reason=reason)
    )
    doc.updated_at = now


def check_revocation(doc: RevocationDocument, fingerprint: str) -> None:
    """Check if a fingerprint is revoked in the standalone document.

    Raises:
        ValueError: If the key is revoked.
    """
    for key in doc.revoked_keys:
        if key.fingerprint == fingerprint:
            raise ValueError(
                f"Key {fingerprint} is revoked: {key.reason.value}"
            )


def check_revocation_combined(
    simple_revoked: Optional[List[str]],
    revocation_doc: Optional[RevocationDocument],
    fingerprint: str,
) -> None:
    """Check revocation against both simple list and standalone document.

    Raises:
        ValueError: If the key is revoked in either source.
    """
    if simple_revoked:
        if fingerprint in simple_revoked:
            raise ValueError(f"Key {fingerprint} is in simple revocation list")

    if revocation_doc is not None:
        check_revocation(revocation_doc, fingerprint)


def fetch_revocation_document(
    url: str, timeout: int = 10
) -> Optional[RevocationDocument]:
    """Fetch a standalone revocation document from a URL.

    Returns:
        RevocationDocument if successful, None on failure.
    """
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        return RevocationDocument.from_dict(data)
    except Exception:
        return None
