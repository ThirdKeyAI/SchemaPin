"""Offline and resolver-based schema verification for SchemaPin v1.2."""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from .core import SchemaPinCore
from .crypto import KeyManager, SignatureManager
from .dns import DnsTxtRecord, verify_dns_match
from .domain import InvalidDomainError, validate_domain
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
    # v1.4 alpha.3: signature declared a canonicalization algorithm this
    # verifier does not support. Hard failure.
    CANONICALIZATION_UNSUPPORTED = "canonicalization_unsupported"
    # v1.4 alpha.3: A2A scope violation (provider domain not in caller's
    # trusted_domains, or delegation_depth exceeded).
    A2A_SCOPE_VIOLATION = "a2a_scope_violation"
    # v1.4: a trust bundle was passed to verify_trust_bundle without a
    # bundle_authority / signature pair. Bundle distribution requires a
    # signed bundle.
    BUNDLE_UNSIGNED = "bundle_unsigned"
    # v1.4: a signed trust bundle's expires_at is in the past (or unparseable).
    BUNDLE_EXPIRED = "bundle_expired"
    # A signature's ``expires_at`` is in the past (or unparseable) and the
    # caller did not opt in with ``allow_expired=True``. Hard failure.
    SIGNATURE_EXPIRED = "signature_expired"
    # The caller-supplied domain is not a valid RFC 1123 hostname.
    DOMAIN_INVALID = "domain_invalid"
    # A trust bundle's authority key is not pre-seeded in the authority store
    # and the caller did not opt in to first-use trust.
    BUNDLE_AUTHORITY_UNTRUSTED = "bundle_authority_untrusted"


#: Clock-skew tolerance applied to ``expires_at`` comparisons (seconds).
EXPIRATION_SKEW_SECONDS = 300


# v1.4 alpha.3: canonicalization algorithm identifier
#
# Signatures MAY carry a ``canonicalization`` field naming the algorithm used
# to produce the signing input. Absence is equivalent to ``CANONICALIZATION_V1``
# for backward compatibility with v1.3 signatures. Verifiers MUST reject any
# other value as ``CANONICALIZATION_UNSUPPORTED``.
CANONICALIZATION_V1 = "schemapin-v1"


def check_canonicalization(algorithm: Optional[str]) -> Optional[str]:
    """Return ``None`` when ``algorithm`` is supported, or the offending value.

    ``None`` or ``"schemapin-v1"`` are equivalent and supported. Any other
    value is unsupported and the caller surfaces it as
    ``ErrorCode.CANONICALIZATION_UNSUPPORTED``.
    """
    if algorithm is None or algorithm == CANONICALIZATION_V1:
        return None
    return algorithm


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
        self,
        expires_at: Optional[str],
        allow_expired: bool = False,
        skew_seconds: int = EXPIRATION_SKEW_SECONDS,
    ) -> "VerificationResult":
        """Apply a signature ``expires_at`` check to this result.

        Expiration is **fail-closed** by default:

        - ``expires_at`` of ``None`` leaves the result unchanged.
        - A value that is not strict RFC 3339 fails with
          ``SIGNATURE_EXPIRED`` (``allow_expired=True`` downgrades this to a
          ``signature_expires_at_unparseable`` warning).
        - A timestamp more than ``skew_seconds`` in the past fails with
          ``SIGNATURE_EXPIRED`` and sets ``expired = True``. With
          ``allow_expired=True`` the result stays valid but is marked
          ``expired`` and carries a ``signature_expired`` warning
          (the pre-1.4.0 "degraded, not failed" behavior).
        - A future timestamp just records ``expires_at``.

        Returns ``self`` for chaining.
        """
        if expires_at is None:
            return self
        ts = _parse_rfc3339(expires_at)
        if ts is None:
            if allow_expired:
                self.warnings.append("signature_expires_at_unparseable")
                return self
            self.valid = False
            self.error_code = ErrorCode.SIGNATURE_EXPIRED
            self.error_message = f"expires_at is not a valid RFC 3339 timestamp: {expires_at!r}"
            return self
        self.expires_at = expires_at
        if datetime.now(timezone.utc) > ts + timedelta(seconds=skew_seconds):
            self.expired = True
            if allow_expired:
                self.warnings.append("signature_expired")
            else:
                self.valid = False
                self.error_code = ErrorCode.SIGNATURE_EXPIRED
                self.error_message = f"signature expired at {expires_at}"
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


_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$"
)


def _parse_rfc3339(value: str) -> Optional[datetime]:
    """Parse a strict RFC 3339 timestamp (``T`` separator, mandatory offset).

    Accepts ``...Z`` and ``...+HH:MM`` forms only. Date-only strings, local
    times without an offset and other ISO 8601 variants return ``None``.
    """
    if not isinstance(value, str) or not _RFC3339_RE.match(value):
        return None
    try:
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        ts = datetime.fromisoformat(normalized)
    except (TypeError, ValueError):
        return None
    if ts.tzinfo is None:
        return None
    return ts.astimezone(timezone.utc)


class KeyPinStore:
    """Lightweight in-memory fingerprint-based pin store.

    Keys are stored by ``tool_id@domain``. Verification flows use
    :meth:`check` before the signature check and :meth:`pin` only after it
    succeeds, so a failed verification never leaves a pin behind. Operators
    can pre-seed expected fingerprints with :meth:`seed`.
    """

    def __init__(self) -> None:
        self._pins: Dict[str, str] = {}

    def _key(self, tool_id: str, domain: str) -> str:
        return f"{tool_id}@{domain}"

    def check(self, tool_id: str, domain: str, fingerprint: str) -> str:
        """Compare ``fingerprint`` with the pinned value without mutating.

        Returns:
            "first_use" if nothing is pinned for this tool@domain,
            "pinned" if the fingerprint matches,
            "changed" if a different fingerprint is pinned.
        """
        existing = self._pins.get(self._key(tool_id, domain))
        if existing is None:
            return "first_use"
        return "pinned" if existing == fingerprint else "changed"

    def pin(self, tool_id: str, domain: str, fingerprint: str) -> None:
        """Pin ``fingerprint`` for ``tool_id@domain`` (overwrites)."""
        self._pins[self._key(tool_id, domain)] = fingerprint

    def seed(self, tool_id: str, domain: str, fingerprint: str) -> None:
        """Pre-seed an expected fingerprint (out-of-band trust establishment)."""
        self.pin(tool_id, domain, fingerprint)

    def check_and_pin(
        self, tool_id: str, domain: str, fingerprint: str
    ) -> str:
        """Check and pin on first use in one step.

        Prefer :meth:`check` + :meth:`pin` so that pinning can be deferred
        until after signature verification.

        Returns:
            "first_use" if this is a new tool@domain (key is pinned).
            "pinned" if the fingerprint matches the pinned key.
            "changed" if the fingerprint differs from the pinned key.
        """
        result = self.check(tool_id, domain, fingerprint)
        if result == "first_use":
            self.pin(tool_id, domain, fingerprint)
        return result

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
        data = json.loads(json_str)
        if not isinstance(data, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in data.items()
        ):
            raise ValueError("pin store JSON must be an object of string fingerprints")
        store._pins = data
        return store


def verify_schema_offline(
    schema: Dict[str, Any],
    signature_b64: str,
    domain: str,
    tool_id: str,
    discovery: Dict[str, Any],
    revocation: Optional[RevocationDocument],
    pin_store: KeyPinStore,
    canonicalization: Optional[str] = None,
) -> VerificationResult:
    """Verify a schema offline using pre-fetched discovery and revocation data.

    Verification flow:
    1. Validate the canonicalization identifier and the domain syntax
    2. Validate discovery document
    3. Extract public key and compute fingerprint
    4. Check revocation (both simple list + standalone doc)
    5. TOFU pin check (read-only)
    6. Canonicalize schema, compute hash, verify ECDSA signature
    7. Pin the key on first use (only after a successful verification)
    8. Return structured result

    ``canonicalization`` is a v1.4 addition: when the signature carries a
    ``canonicalization`` field, the caller passes the value through.
    ``None`` or ``"schemapin-v1"`` are equivalent and accepted; any other
    value fails with ``CANONICALIZATION_UNSUPPORTED`` before any crypto work.
    """
    # Step 1: canonicalization algorithm + domain syntax
    unsupported = check_canonicalization(canonicalization)
    if unsupported is not None:
        return VerificationResult(
            valid=False,
            domain=domain,
            error_code=ErrorCode.CANONICALIZATION_UNSUPPORTED,
            error_message=f"Unsupported canonicalization algorithm: {unsupported}",
        )
    try:
        domain = validate_domain(domain)
    except InvalidDomainError as e:
        return VerificationResult(
            valid=False,
            domain=domain,
            error_code=ErrorCode.DOMAIN_INVALID,
            error_message=str(e),
        )

    # Step 2: Validate discovery document
    public_key_pem = discovery.get("public_key_pem")
    if not public_key_pem or "-----BEGIN PUBLIC KEY-----" not in public_key_pem:
        return VerificationResult(
            valid=False,
            domain=domain,
            error_code=ErrorCode.DISCOVERY_INVALID,
            error_message="Discovery document missing or invalid public_key_pem",
        )

    # Step 3: Extract public key and compute fingerprint
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

    # Step 4: Check revocation
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

    # Step 5: TOFU pin check (no write yet)
    pin_result = pin_store.check(tool_id, domain, fingerprint)
    if pin_result == "changed":
        return VerificationResult(
            valid=False,
            domain=domain,
            error_code=ErrorCode.KEY_PIN_MISMATCH,
            error_message="Key fingerprint changed since last use",
        )

    # Step 6: Canonicalize, hash, verify
    try:
        schema_hash = SchemaPinCore.canonicalize_and_hash(schema)
    except Exception as e:
        return VerificationResult(
            valid=False,
            domain=domain,
            error_code=ErrorCode.SCHEMA_CANONICALIZATION_FAILED,
            error_message=f"Failed to canonicalize schema: {e}",
        )

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

    # Step 7: Pin only after the signature verified
    if pin_result == "first_use":
        pin_store.pin(tool_id, domain, fingerprint)

    # Step 8: Return success
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


def verify_schema_offline_with_dns(
    schema: Dict[str, Any],
    signature_b64: str,
    domain: str,
    tool_id: str,
    discovery: Dict[str, Any],
    revocation: Optional[RevocationDocument],
    pin_store: KeyPinStore,
    dns_txt: Optional[DnsTxtRecord],
    canonicalization: Optional[str] = None,
) -> VerificationResult:
    """:func:`verify_schema_offline` plus a DNS TXT second-channel check.

    When ``dns_txt`` is given (see :func:`schemapin.dns.fetch_dns_txt`), the
    discovery key's fingerprint must match the TXT record or the result is a
    hard ``DOMAIN_MISMATCH`` failure. The DNS check runs *before* the pin is
    written so a mismatching key is never pinned.
    """
    if dns_txt is not None:
        try:
            verify_dns_match(discovery, dns_txt)
        except ValueError as e:
            return VerificationResult(
                valid=False,
                domain=domain,
                error_code=ErrorCode.DOMAIN_MISMATCH,
                error_message=str(e),
            )
    return verify_schema_offline(
        schema,
        signature_b64,
        domain,
        tool_id,
        discovery,
        revocation,
        pin_store,
        canonicalization,
    )


def verify_schema_with_resolver(
    schema: Dict[str, Any],
    signature_b64: str,
    domain: str,
    tool_id: str,
    resolver: SchemaResolver,
    pin_store: KeyPinStore,
    allow_unreachable_revocation: bool = False,
) -> VerificationResult:
    """Verify a schema using a resolver for discovery and revocation.

    Revocation is fail-closed: if the discovery document declares a
    ``revocation_endpoint`` that cannot be fetched, verification fails with
    ``DISCOVERY_FETCH_FAILED`` unless ``allow_unreachable_revocation=True``.
    """
    from .revocation import RevocationFetchError

    try:
        domain = validate_domain(domain)
    except InvalidDomainError as e:
        return VerificationResult(
            valid=False,
            domain=domain,
            error_code=ErrorCode.DOMAIN_INVALID,
            error_message=str(e),
        )

    # Resolve discovery
    discovery = resolver.resolve_discovery(domain)
    if discovery is None:
        return VerificationResult(
            valid=False,
            domain=domain,
            error_code=ErrorCode.DISCOVERY_FETCH_FAILED,
            error_message=f"Could not resolve discovery for domain: {domain}",
        )

    # Resolve revocation (fail-closed)
    try:
        revocation = resolver.resolve_revocation(domain, discovery)
    except RevocationFetchError as e:
        if not allow_unreachable_revocation:
            return VerificationResult(
                valid=False,
                domain=domain,
                error_code=ErrorCode.DISCOVERY_FETCH_FAILED,
                error_message=f"Revocation document unreachable (fail-closed): {e}",
            )
        revocation = None

    return verify_schema_offline(
        schema, signature_b64, domain, tool_id, discovery, revocation, pin_store
    )


# v1.4 alpha.3 — A2A context verification
#
# Mirrors AgentPin's max_delegation_depth cap (AgentPin spec §4.3). Bumping
# this on the SchemaPin side without a matching bump on AgentPin would let
# SchemaPin accept chains AgentPin would reject — keep in lockstep.
A2A_MAX_DELEGATION_DEPTH = 3


def verify_schema_for_a2a(
    schema: Dict[str, Any],
    signature_b64: str,
    domain: str,
    tool_id: str,
    discovery: Dict[str, Any],
    revocation: Optional[RevocationDocument],
    pin_store: KeyPinStore,
    context,  # forward reference to schemapin.a2a.A2aVerificationContext
    canonicalization: Optional[str] = None,
) -> VerificationResult:
    """Verify a schema in the context of an A2A interaction (v1.4 alpha.3).

    Wraps :func:`verify_schema_offline` with an A2A scope check:

    1. Reject when ``context.delegation_depth > A2A_MAX_DELEGATION_DEPTH``.
       Surfaces as ``A2A_SCOPE_VIOLATION``.
    2. Run the standard 7-step verification. If it fails, return that
       result unchanged.
    3. Reject when ``context.trusted_domains`` is non-empty and ``domain``
       is not allowed by it. Surfaces as ``A2A_SCOPE_VIOLATION``.

    On success the returned :class:`VerificationResult` is the result from
    step 2 unchanged — A2A context does not modify the cryptographic
    outcome, only the policy outcome.
    """
    # Local import to avoid a circular dependency: schemapin.a2a doesn't
    # depend on verification, and we don't want verification to require a2a
    # at import time for callers that don't use the A2A surface.
    from .a2a import allows as a2a_allows

    if context.delegation_depth > A2A_MAX_DELEGATION_DEPTH:
        return VerificationResult(
            valid=False,
            domain=domain,
            error_code=ErrorCode.A2A_SCOPE_VIOLATION,
            error_message=(
                f"A2A delegation_depth {context.delegation_depth} exceeds cap of "
                f"{A2A_MAX_DELEGATION_DEPTH}"
            ),
        )

    result = verify_schema_offline(
        schema,
        signature_b64,
        domain,
        tool_id,
        discovery,
        revocation,
        pin_store,
        canonicalization,
    )
    if not result.valid:
        return result

    if not a2a_allows(context.trusted_domains, domain):
        return VerificationResult(
            valid=False,
            domain=domain,
            error_code=ErrorCode.A2A_SCOPE_VIOLATION,
            error_message=(
                f"Provider domain '{domain}' not in caller's A2A "
                f"trusted_domains scope"
            ),
        )

    return result
