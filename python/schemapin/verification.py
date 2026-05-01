"""Offline and resolver-based schema verification for SchemaPin v1.2."""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from .core import SchemaPinCore
from .crypto import KeyManager, SignatureManager
from .resolver import SchemaResolver
from .revocation import RevocationDocument, check_revocation_combined


class ErrorCode(Enum):
    """Structured error codes for verification results."""

    SIGNATURE_INVALID = "signature_invalid"
    KEY_NOT_FOUND = "key_not_found"
    KEY_REVOKED = "key_revoked"
    KEY_PIN_MISMATCH = "key_pin_mismatch"
    DISCOVERY_FETCH_FAILED = "discovery_fetch_failed"
    DISCOVERY_INVALID = "discovery_invalid"
    DOMAIN_MISMATCH = "domain_mismatch"
    SCHEMA_CANONICALIZATION_FAILED = "schema_canonicalization_failed"


@dataclass
class KeyPinningStatus:
    """Status of key pinning for a verification result."""

    status: str  # "first_use" or "pinned"
    first_seen: Optional[str] = None


@dataclass
class VerificationResult:
    """Structured result from schema verification."""

    valid: bool
    domain: Optional[str] = None
    developer_name: Optional[str] = None
    key_pinning: Optional[KeyPinningStatus] = None
    error_code: Optional[ErrorCode] = None
    error_message: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    # v1.4: signature expiration metadata.
    #
    # ``expired`` is True only when the signature carried an ``expires_at``
    # that has already passed. ``valid`` remains True (degraded, not failed)
    # so callers can use this flag for confidence scoring or policy gating.
    expired: bool = False
    expires_at: Optional[str] = None
    # v1.4 alpha.2: schema_version + previous_hash lineage metadata, mirrored
    # from the signature when present. ``schema_version`` is the caller's
    # semver string identifying *this* version of the artifact. ``previous_hash``
    # is the ``sha256:<hex>`` of the prior signed version's ``skill_hash``
    # (pair with ``schemapin.skill.verify_chain`` to confirm lineage).
    schema_version: Optional[str] = None
    previous_hash: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        d: Dict[str, Any] = {"valid": self.valid}
        if self.domain is not None:
            d["domain"] = self.domain
        if self.developer_name is not None:
            d["developer_name"] = self.developer_name
        if self.key_pinning is not None:
            d["key_pinning"] = {
                "status": self.key_pinning.status,
            }
            if self.key_pinning.first_seen is not None:
                d["key_pinning"]["first_seen"] = self.key_pinning.first_seen
        if self.error_code is not None:
            d["error_code"] = self.error_code.value
        if self.error_message is not None:
            d["error_message"] = self.error_message
        if self.warnings:
            d["warnings"] = self.warnings
        if self.expired:
            d["expired"] = True
        if self.expires_at is not None:
            d["expires_at"] = self.expires_at
        if self.schema_version is not None:
            d["schema_version"] = self.schema_version
        if self.previous_hash is not None:
            d["previous_hash"] = self.previous_hash
        return d

    def with_expiration_check(
        self, expires_at: Optional[str]
    ) -> "VerificationResult":
        """Apply a signature ``expires_at`` check to this result.

        Semantics (mirrors the Rust ``VerificationResult::with_expiration_check``):

        - If ``expires_at`` is ``None``, the result is returned unchanged.
        - If parseable (RFC 3339) and in the past, sets ``expired = True``,
          copies ``expires_at``, and appends a ``signature_expired`` warning.
          ``valid`` is left intact (degraded, not failed).
        - If parseable and in the future, just records ``expires_at``.
        - If unparseable, appends ``signature_expires_at_unparseable`` and
          does not mark the result expired (fail-open on parse).

        Returns ``self`` for chaining.
        """
        if expires_at is None:
            return self
        ts = _parse_rfc3339(expires_at)
        if ts is None:
            self.warnings.append("signature_expires_at_unparseable")
            return self
        self.expires_at = expires_at
        if datetime.now(timezone.utc) > ts:
            self.expired = True
            self.warnings.append("signature_expired")
        return self

    def with_lineage_metadata(
        self,
        schema_version: Optional[str],
        previous_hash: Optional[str],
    ) -> "VerificationResult":
        """Copy v1.4 alpha.2 lineage fields onto this result.

        No semantic enforcement -- these are informational fields callers use
        for version policy and chain verification (see
        :func:`schemapin.skill.verify_chain`).

        Returns ``self`` for chaining.
        """
        if schema_version is not None:
            self.schema_version = schema_version
        if previous_hash is not None:
            self.previous_hash = previous_hash
        return self


def _parse_rfc3339(value: str) -> Optional[datetime]:
    """Parse an RFC 3339 timestamp.

    Accepts both ``...Z`` and ``...+HH:MM`` forms. Returns ``None`` on any
    parse failure so callers can branch on success.
    """
    try:
        # Python 3.11+ accepts trailing Z; for 3.8-3.10 normalize manually.
        normalized = value.strip()
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        ts = datetime.fromisoformat(normalized)
    except (TypeError, ValueError):
        return None
    if ts.tzinfo is None:
        # RFC 3339 requires a TZ offset; treat naive timestamps as malformed.
        return None
    return ts.astimezone(timezone.utc)


class KeyPinStore:
    """Lightweight in-memory fingerprint-based pin store.

    Keys are stored by tool_id@domain.
    """

    def __init__(self) -> None:
        self._pins: Dict[str, str] = {}

    def _key(self, tool_id: str, domain: str) -> str:
        return f"{tool_id}@{domain}"

    def check_and_pin(
        self, tool_id: str, domain: str, fingerprint: str
    ) -> str:
        """Check and optionally pin a key fingerprint.

        Returns:
            "first_use" if this is a new tool@domain (key is pinned).
            "pinned" if the fingerprint matches the pinned key.
            "changed" if the fingerprint differs from the pinned key.
        """
        k = self._key(tool_id, domain)
        existing = self._pins.get(k)
        if existing is None:
            self._pins[k] = fingerprint
            return "first_use"
        if existing == fingerprint:
            return "pinned"
        return "changed"

    def get_pinned(self, tool_id: str, domain: str) -> Optional[str]:
        """Get the pinned fingerprint for a tool@domain, or None."""
        return self._pins.get(self._key(tool_id, domain))

    def to_json(self) -> str:
        """Serialize the pin store to JSON."""
        return json.dumps(self._pins)

    @classmethod
    def from_json(cls, json_str: str) -> "KeyPinStore":
        """Deserialize a pin store from JSON."""
        store = cls()
        store._pins = json.loads(json_str)
        return store


def verify_schema_offline(
    schema: Dict[str, Any],
    signature_b64: str,
    domain: str,
    tool_id: str,
    discovery: Dict[str, Any],
    revocation: Optional[RevocationDocument],
    pin_store: KeyPinStore,
) -> VerificationResult:
    """Verify a schema offline using pre-fetched discovery and revocation data.

    7-step verification flow:
    1. Validate discovery document
    2. Extract public key and compute fingerprint
    3. Check revocation (both simple list + standalone doc)
    4. TOFU key pinning check
    5. Canonicalize schema and compute hash
    6. Verify ECDSA signature against hash
    7. Return structured result
    """
    # Step 1: Validate discovery document
    public_key_pem = discovery.get("public_key_pem")
    if not public_key_pem or "-----BEGIN PUBLIC KEY-----" not in public_key_pem:
        return VerificationResult(
            valid=False,
            domain=domain,
            error_code=ErrorCode.DISCOVERY_INVALID,
            error_message="Discovery document missing or invalid public_key_pem",
        )

    # Step 2: Extract public key and compute fingerprint
    try:
        public_key = KeyManager.load_public_key_pem(public_key_pem)
        fingerprint = KeyManager.calculate_key_fingerprint(public_key)
    except Exception as e:
        return VerificationResult(
            valid=False,
            domain=domain,
            error_code=ErrorCode.KEY_NOT_FOUND,
            error_message=f"Failed to load public key: {e}",
        )

    # Step 3: Check revocation
    simple_revoked = discovery.get("revoked_keys", [])
    try:
        check_revocation_combined(simple_revoked, revocation, fingerprint)
    except ValueError as e:
        return VerificationResult(
            valid=False,
            domain=domain,
            error_code=ErrorCode.KEY_REVOKED,
            error_message=str(e),
        )

    # Step 4: TOFU key pinning
    pin_result = pin_store.check_and_pin(tool_id, domain, fingerprint)
    if pin_result == "changed":
        return VerificationResult(
            valid=False,
            domain=domain,
            error_code=ErrorCode.KEY_PIN_MISMATCH,
            error_message="Key fingerprint changed since last use",
        )

    # Step 5: Canonicalize and hash
    try:
        schema_hash = SchemaPinCore.canonicalize_and_hash(schema)
    except Exception as e:
        return VerificationResult(
            valid=False,
            domain=domain,
            error_code=ErrorCode.SCHEMA_CANONICALIZATION_FAILED,
            error_message=f"Failed to canonicalize schema: {e}",
        )

    # Step 6: Verify signature
    valid = SignatureManager.verify_schema_signature(
        schema_hash, signature_b64, public_key
    )

    if not valid:
        return VerificationResult(
            valid=False,
            domain=domain,
            error_code=ErrorCode.SIGNATURE_INVALID,
            error_message="Signature verification failed",
        )

    # Step 7: Return success
    developer_name = discovery.get("developer_name")
    pinning_status = KeyPinningStatus(
        status=pin_result,
        first_seen=None,
    )

    result = VerificationResult(
        valid=True,
        domain=domain,
        developer_name=developer_name,
        key_pinning=pinning_status,
    )

    # Add warnings
    schema_version = discovery.get("schema_version", "")
    if schema_version and schema_version < "1.2":
        result.warnings.append(
            f"Discovery uses schema version {schema_version}, consider upgrading to 1.2"
        )

    return result


def verify_schema_with_resolver(
    schema: Dict[str, Any],
    signature_b64: str,
    domain: str,
    tool_id: str,
    resolver: SchemaResolver,
    pin_store: KeyPinStore,
) -> VerificationResult:
    """Verify a schema using a resolver for discovery and revocation."""
    # Resolve discovery
    discovery = resolver.resolve_discovery(domain)
    if discovery is None:
        return VerificationResult(
            valid=False,
            domain=domain,
            error_code=ErrorCode.DISCOVERY_FETCH_FAILED,
            error_message=f"Could not resolve discovery for domain: {domain}",
        )

    # Resolve revocation
    revocation = resolver.resolve_revocation(domain, discovery)

    return verify_schema_offline(
        schema, signature_b64, domain, tool_id, discovery, revocation, pin_store
    )
