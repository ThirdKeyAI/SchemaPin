"""(v1.4) Trust-bundle distribution for A2A networks.

Lets a *bundle authority* sign a :class:`~schemapin.bundle.SchemaPinTrustBundle`
so it can be exchanged between agents over A2A without per-bundle out-of-band
trust establishment. Provides:

- :func:`sign_trust_bundle` / :func:`verify_trust_bundle` -- ECDSA P-256 over
  the canonical bundle bytes, with an **authority allow-list**: the authority
  key must be pre-seeded in the authority store (see
  :func:`seed_bundle_authority`) unless the caller explicitly opts in to
  first-use trust.
- :func:`merge_trust_bundles` -- combine bundles from multiple sources with
  per-authority precedence and parsed-timestamp tie-breaking.
- :func:`build_trust_bundle_request` / :func:`build_trust_bundle_response` /
  :func:`parse_trust_bundle_response` -- the ``schemapin/trustBundle`` JSON-RPC
  envelope for A2A bundle exchange.

Signing input
-------------

The signature covers the ``schemapin-v1`` canonicalization of the bundle's
**known fields** (unknown fields are ignored and therefore unprotected) with
``signature`` set to ``""``. The field set mirrors the Rust reference
serialization exactly: optional strings are omitted when absent, and
``revoked_keys`` / ``revocations`` are always present (possibly empty). All
four SDKs build the identical byte string, so a bundle signed by any SDK
verifies in every other.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .bundle import BundleAuthority, SchemaPinTrustBundle
from .core import SchemaPinCore
from .crypto import KeyManager, SignatureManager
from .verification import ErrorCode, KeyPinStore, _parse_rfc3339

#: Bundle-distribution wire format version stamped on signed bundles.
BUNDLE_VERSION_SIGNED = "1.4"

#: Sentinel "domain" used to key bundle-authority pins in a ``KeyPinStore``.
#: Authorities are pinned by ``kid``, independent of any tool domain.
BUNDLE_AUTHORITY_PIN_DOMAIN = "_bundle_authority"

_DOCUMENT_OPTIONAL_FIELDS = ("developer_name", "contact", "revocation_endpoint")


class BundleVerificationError(Exception):
    """Raised when a trust bundle fails verification.

    Carries a structured :class:`~schemapin.verification.ErrorCode` (e.g.
    ``BUNDLE_UNSIGNED``, ``BUNDLE_EXPIRED``, ``BUNDLE_AUTHORITY_UNTRUSTED``,
    ``KEY_PIN_MISMATCH``, ``SIGNATURE_INVALID``) alongside the message.
    """

    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class BundleVerification:
    """Successful :func:`verify_trust_bundle` outcome.

    ``first_use`` is ``True`` when the authority key was not pre-seeded and
    the caller allowed first-use trust; hosts should surface this to the user
    exactly like a first-use tool key.
    """

    kid: str
    fingerprint: str
    first_use: bool


def _normalize_document(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Project a bundled discovery entry onto the signed field set."""
    out: Dict[str, Any] = {
        "domain": doc.get("domain", ""),
        "schema_version": doc.get("schema_version", ""),
        "public_key_pem": doc.get("public_key_pem", ""),
        "revoked_keys": list(doc.get("revoked_keys") or []),
    }
    for key in _DOCUMENT_OPTIONAL_FIELDS:
        value = doc.get(key)
        if value is not None:
            out[key] = value
    return out


def _signing_value(bundle: SchemaPinTrustBundle) -> Dict[str, Any]:
    obj: Dict[str, Any] = {
        "schemapin_bundle_version": bundle.schemapin_bundle_version,
        "created_at": bundle.created_at,
        "documents": [_normalize_document(d) for d in bundle.documents],
        "revocations": [r.to_dict() for r in bundle.revocations],
    }
    if bundle.bundle_authority is not None:
        obj["bundle_authority"] = bundle.bundle_authority.to_dict()
    if bundle.signed_at is not None:
        obj["signed_at"] = bundle.signed_at
    if bundle.expires_at is not None:
        obj["expires_at"] = bundle.expires_at
    obj["signature"] = ""
    return obj


def _signing_bytes(bundle: SchemaPinTrustBundle) -> bytes:
    """Build the canonical bytes a bundle's signature covers."""
    return SchemaPinCore.canonicalize_schema(_signing_value(bundle)).encode("utf-8")


def _duplicate_domain(bundle: SchemaPinTrustBundle) -> Optional[str]:
    seen: set = set()
    for d in bundle.documents:
        domain = d.get("domain")
        if domain in seen:
            return str(domain)
        seen.add(domain)
    seen = set()
    for r in bundle.revocations:
        if r.domain in seen:
            return r.domain
        seen.add(r.domain)
    return None


def seed_bundle_authority(
    store: KeyPinStore, kid: str, fingerprint: str
) -> None:
    """Pre-seed the expected fingerprint (``sha256:<hex>``) of a bundle authority.

    This is the allow-list entry :func:`verify_trust_bundle` requires. Obtain
    the fingerprint out of band -- for example from the authority's own
    ``.well-known/schemapin.json`` via :func:`seed_bundle_authority_from_pem`
    with the discovery document's ``public_key_pem``.
    """
    store.seed(kid, BUNDLE_AUTHORITY_PIN_DOMAIN, fingerprint)


def seed_bundle_authority_from_pem(
    store: KeyPinStore, kid: str, public_key_pem: str
) -> str:
    """Seed an authority from its PEM public key; returns the fingerprint."""
    fingerprint = KeyManager.calculate_key_fingerprint_from_pem(public_key_pem)
    seed_bundle_authority(store, kid, fingerprint)
    return fingerprint


def sign_trust_bundle(
    bundle: SchemaPinTrustBundle,
    private_key_pem: str,
    kid: str,
    signed_at: str,
    expires_at: Optional[str] = None,
) -> SchemaPinTrustBundle:
    """Sign a trust bundle with a bundle-authority key.

    Stamps ``bundle_authority`` (derived public key + ``kid``),
    ``schemapin_bundle_version = "1.4"``, ``signed_at``, and optional
    ``expires_at``, then writes the base64 DER ECDSA P-256 ``signature``.
    ``signed_at`` / ``expires_at`` are caller-supplied RFC 3339 strings (kept
    out of the core so signing is deterministic and cross-language testable).

    Raises:
        ValueError: if the bundle contains duplicate domains.
    """
    dup = _duplicate_domain(bundle)
    if dup is not None:
        raise ValueError(f"trust bundle has duplicate entries for domain {dup!r}")

    private_key = KeyManager.load_private_key_pem(private_key_pem)
    public_key_pem = KeyManager.export_public_key_pem(private_key.public_key())

    signed = SchemaPinTrustBundle(
        schemapin_bundle_version=BUNDLE_VERSION_SIGNED,
        created_at=bundle.created_at,
        documents=list(bundle.documents),
        revocations=list(bundle.revocations),
        bundle_authority=BundleAuthority(kid=kid, public_key_pem=public_key_pem),
        signed_at=signed_at,
        expires_at=expires_at,
        signature=None,
    )

    canonical = _signing_bytes(signed)
    signed.signature = SignatureManager.sign_hash(canonical, private_key)
    return signed


def verify_trust_bundle(
    bundle: SchemaPinTrustBundle,
    authority_pin_store: KeyPinStore,
    allow_first_use: bool = False,
) -> BundleVerification:
    """Verify a signed trust bundle against the authority allow-list.

    Steps:

    1. require ``bundle_authority`` + ``signature`` (else ``BUNDLE_UNSIGNED``);
    2. reject duplicate domains (``DISCOVERY_INVALID``);
    3. reject when ``expires_at`` is in the past or unparseable
       (``BUNDLE_EXPIRED``);
    4. look the authority's key fingerprint up by ``kid`` in
       ``authority_pin_store``: a different pinned key is
       ``KEY_PIN_MISMATCH``; an unknown ``kid`` is
       ``BUNDLE_AUTHORITY_UNTRUSTED`` unless ``allow_first_use=True``;
    5. verify the signature over the canonical bytes
       (``SIGNATURE_INVALID``);
    6. pin the authority on first use (only after the signature verified).

    The bundle carries its own public key, so without an allow-list any
    self-signed bundle under a fresh ``kid`` would pass. Seed expected
    authorities with :func:`seed_bundle_authority`; treat ``allow_first_use``
    exactly like TOFU for a tool key (prompt the user, log it).

    Returns a :class:`BundleVerification`; raises
    :class:`BundleVerificationError` otherwise.
    """
    authority = bundle.bundle_authority
    if authority is None:
        raise BundleVerificationError(
            ErrorCode.BUNDLE_UNSIGNED, "trust bundle has no bundle_authority"
        )
    signature = bundle.signature
    if signature is None:
        raise BundleVerificationError(
            ErrorCode.BUNDLE_UNSIGNED, "trust bundle has no signature"
        )

    dup = _duplicate_domain(bundle)
    if dup is not None:
        raise BundleVerificationError(
            ErrorCode.DISCOVERY_INVALID,
            f"trust bundle has duplicate entries for domain {dup!r}",
        )

    if bundle.expires_at is not None:
        exp = _parse_rfc3339(bundle.expires_at)
        if exp is None:
            raise BundleVerificationError(
                ErrorCode.BUNDLE_EXPIRED,
                f"unparseable expires_at '{bundle.expires_at}'",
            )
        if datetime.now(timezone.utc) > exp:
            raise BundleVerificationError(
                ErrorCode.BUNDLE_EXPIRED,
                f"trust bundle expired at {bundle.expires_at}",
            )

    try:
        fingerprint = KeyManager.calculate_key_fingerprint_from_pem(
            authority.public_key_pem
        )
    except Exception as e:
        raise BundleVerificationError(
            ErrorCode.KEY_NOT_FOUND, f"bundle authority key is invalid: {e}"
        ) from e
    pin_result = authority_pin_store.check(
        authority.kid, BUNDLE_AUTHORITY_PIN_DOMAIN, fingerprint
    )
    if pin_result == "changed":
        raise BundleVerificationError(
            ErrorCode.KEY_PIN_MISMATCH,
            f"bundle authority key for kid '{authority.kid}' does not match the "
            f"seeded authority key",
        )
    if pin_result == "first_use" and not allow_first_use:
        raise BundleVerificationError(
            ErrorCode.BUNDLE_AUTHORITY_UNTRUSTED,
            f"bundle authority kid '{authority.kid}' is not in the authority "
            f"allow-list; seed it with seed_bundle_authority() or pass "
            f"allow_first_use=True",
        )

    canonical = _signing_bytes(bundle)
    public_key = KeyManager.load_public_key_pem(authority.public_key_pem)
    if not SignatureManager.verify_signature(canonical, signature, public_key):
        raise BundleVerificationError(
            ErrorCode.SIGNATURE_INVALID,
            "trust bundle signature does not verify",
        )

    if pin_result == "first_use":
        authority_pin_store.pin(authority.kid, BUNDLE_AUTHORITY_PIN_DOMAIN, fingerprint)
    return BundleVerification(
        kid=authority.kid, fingerprint=fingerprint, first_use=pin_result == "first_use"
    )


def _bundle_timestamp(bundle: SchemaPinTrustBundle) -> str:
    """Sort timestamp for a bundle: ``signed_at`` if present, else ``created_at``."""
    return bundle.signed_at if bundle.signed_at is not None else bundle.created_at


def _merge_rank(
    bundle: SchemaPinTrustBundle, precedence: Optional[Sequence[str]]
) -> Tuple[int, datetime]:
    """Higher tuple wins: (authority precedence, parsed timestamp)."""
    kid = bundle.bundle_authority.kid if bundle.bundle_authority else None
    rank = 0
    if precedence:
        rank = -len(precedence) - 1
        if kid is not None and kid in precedence:
            rank = -list(precedence).index(kid)
    ts = _parse_rfc3339(_bundle_timestamp(bundle)) or datetime.min.replace(
        tzinfo=timezone.utc
    )
    return rank, ts


def merge_trust_bundles(
    bundles: List[SchemaPinTrustBundle],
    authority_precedence: Optional[Sequence[str]] = None,
) -> SchemaPinTrustBundle:
    """Merge trust bundles, deduplicating discovery + revocation documents by
    domain.

    When two bundles carry the same domain the winner is chosen by
    ``authority_precedence`` first (a list of authority ``kid`` values,
    earlier wins; bundles from unlisted or absent authorities rank last) and
    by the newer **parsed** RFC 3339 timestamp (``signed_at``, else
    ``created_at``) second. Unparseable timestamps rank oldest, so a bundle
    cannot win a merge by claiming a bogus future date.

    Merge only bundles you have already verified with
    :func:`verify_trust_bundle`.

    The result is an *unsigned* bundle stamped
    ``schemapin_bundle_version = "1.4"`` with ``created_at`` set to the
    newest source timestamp. Re-sign it with :func:`sign_trust_bundle`
    before redistribution.
    """
    docs: Dict[str, Any] = {}  # domain -> (rank, document)
    revs: Dict[str, Any] = {}  # domain -> (rank, RevocationDocument)
    newest_ts: Optional[datetime] = None
    newest_raw = ""

    for b in bundles:
        rank = _merge_rank(b, authority_precedence)
        if newest_ts is None or rank[1] > newest_ts:
            newest_ts = rank[1]
            newest_raw = _bundle_timestamp(b)
        for d in b.documents:
            domain = d.get("domain")
            existing = docs.get(domain)
            if existing is None or existing[0] < rank:
                docs[domain] = (rank, d)
        for r in b.revocations:
            existing = revs.get(r.domain)
            if existing is None or existing[0] < rank:
                revs[r.domain] = (rank, r)

    documents = [v[1] for v in docs.values()]
    documents.sort(key=lambda d: d.get("domain", ""))
    revocations = [v[1] for v in revs.values()]
    revocations.sort(key=lambda r: r.domain)

    return SchemaPinTrustBundle(
        schemapin_bundle_version=BUNDLE_VERSION_SIGNED,
        created_at=newest_raw,
        documents=documents,
        revocations=revocations,
    )


def build_trust_bundle_request(
    domain: Optional[str] = None, id: Any = None
) -> Dict[str, Any]:
    """Build a ``schemapin/trustBundle`` JSON-RPC request. ``domain`` optionally
    scopes the request to a single provider; omit for "send your whole bundle".
    """
    params: Dict[str, Any] = {"domain": domain} if domain is not None else {}
    return {
        "jsonrpc": "2.0",
        "method": "schemapin/trustBundle",
        "params": params,
        "id": id,
    }


def build_trust_bundle_response(
    bundle: SchemaPinTrustBundle, id: Any = None
) -> Dict[str, Any]:
    """Build a ``schemapin/trustBundle`` JSON-RPC response carrying a bundle."""
    return {
        "jsonrpc": "2.0",
        "result": {"bundle": bundle.to_dict()},
        "id": id,
    }


def parse_trust_bundle_response(
    response: Dict[str, Any],
) -> SchemaPinTrustBundle:
    """Extract the bundle from a ``schemapin/trustBundle`` JSON-RPC response."""
    result = response.get("result")
    bundle = result.get("bundle") if isinstance(result, dict) else None
    if bundle is None:
        raise BundleVerificationError(
            ErrorCode.DISCOVERY_INVALID,
            "JSON-RPC response missing result.bundle",
        )
    return SchemaPinTrustBundle.from_dict(bundle)
