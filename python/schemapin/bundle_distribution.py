"""(v1.4) Trust-bundle distribution for A2A networks.

Lets a *bundle authority* sign a :class:`~schemapin.bundle.SchemaPinTrustBundle`
so it can be exchanged between agents over A2A without per-bundle out-of-band
trust establishment. Provides:

- :func:`sign_trust_bundle` / :func:`verify_trust_bundle` — ECDSA P-256 over
  the canonical bundle bytes, with TOFU pinning of the authority key by ``kid``.
- :func:`merge_trust_bundles` — combine bundles from multiple sources, newest
  entry wins per domain.
- :func:`build_trust_bundle_request` / :func:`build_trust_bundle_response` /
  :func:`parse_trust_bundle_response` — the ``schemapin/trustBundle`` JSON-RPC
  envelope for A2A bundle exchange.

Signing input
-------------

The signature covers the ``schemapin-v1`` canonicalization (recursive sorted
keys, compact, UTF-8) of the entire bundle object with the ``signature`` field
set to the empty string ``""``. All four SDKs build the identical byte string,
so a bundle signed by any SDK verifies in every other.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .bundle import BundleAuthority, SchemaPinTrustBundle
from .core import SchemaPinCore
from .crypto import KeyManager, SignatureManager
from .verification import ErrorCode, KeyPinStore, _parse_rfc3339

#: Bundle-distribution wire format version stamped on signed bundles.
BUNDLE_VERSION_SIGNED = "1.4"

#: Sentinel "domain" used to key bundle-authority pins in a ``KeyPinStore``.
#: Authorities are pinned by ``kid``, independent of any tool domain.
BUNDLE_AUTHORITY_PIN_DOMAIN = "_bundle_authority"


class BundleVerificationError(Exception):
    """Raised when a trust bundle fails verification.

    Carries a structured :class:`~schemapin.verification.ErrorCode` (e.g.
    ``BUNDLE_UNSIGNED``, ``BUNDLE_EXPIRED``, ``KEY_PIN_MISMATCH``,
    ``SIGNATURE_INVALID``) alongside the human-readable message.
    """

    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _signing_bytes(bundle: SchemaPinTrustBundle) -> bytes:
    """Build the canonical bytes a bundle's signature covers: the bundle with
    its ``signature`` field forced to ``""``, ``schemapin-v1``-canonicalized.
    """
    obj = bundle.to_dict()
    obj["signature"] = ""
    canonical = SchemaPinCore.canonicalize_schema(obj)
    return canonical.encode("utf-8")


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
    """
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
) -> None:
    """Verify a signed trust bundle and TOFU-pin its authority key by ``kid``.

    Steps: require ``bundle_authority`` + ``signature`` (else
    ``BUNDLE_UNSIGNED``); reject when ``expires_at`` is in the past or
    unparseable (``BUNDLE_EXPIRED``); TOFU-pin the authority's key fingerprint
    by ``kid`` (mismatch → ``KEY_PIN_MISMATCH``); verify the signature over the
    canonical bytes (failure → ``SIGNATURE_INVALID``).

    Returns ``None`` on success; raises :class:`BundleVerificationError`
    otherwise.
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

    fingerprint = KeyManager.calculate_key_fingerprint_from_pem(
        authority.public_key_pem
    )
    pin_result = authority_pin_store.check_and_pin(
        authority.kid, BUNDLE_AUTHORITY_PIN_DOMAIN, fingerprint
    )
    if pin_result == "changed":
        raise BundleVerificationError(
            ErrorCode.KEY_PIN_MISMATCH,
            f"bundle authority key for kid '{authority.kid}' changed since "
            f"first use",
        )

    canonical = _signing_bytes(bundle)
    public_key = KeyManager.load_public_key_pem(authority.public_key_pem)
    if not SignatureManager.verify_signature(canonical, signature, public_key):
        raise BundleVerificationError(
            ErrorCode.SIGNATURE_INVALID,
            "trust bundle signature does not verify",
        )


def _bundle_timestamp(bundle: SchemaPinTrustBundle) -> str:
    """Sort timestamp for a bundle: ``signed_at`` if present, else ``created_at``."""
    return bundle.signed_at if bundle.signed_at is not None else bundle.created_at


def merge_trust_bundles(
    bundles: List[SchemaPinTrustBundle],
) -> SchemaPinTrustBundle:
    """Merge trust bundles, deduplicating discovery + revocation documents by
    domain. When two bundles carry the same domain, the entry from the bundle
    with the newer timestamp (``signed_at``, else ``created_at``) wins.

    The result is an *unsigned* bundle (a merge cannot carry a single
    authority's signature) stamped ``schemapin_bundle_version = "1.4"`` with
    ``created_at`` set to the newest source timestamp. Re-sign it with
    :func:`sign_trust_bundle` before redistribution.
    """
    docs: Dict[str, Any] = {}  # domain -> (timestamp, document)
    revs: Dict[str, Any] = {}  # domain -> (timestamp, RevocationDocument)
    newest_ts = ""

    for b in bundles:
        ts = _bundle_timestamp(b)
        if ts > newest_ts:
            newest_ts = ts
        for d in b.documents:
            domain = d.get("domain")
            existing = docs.get(domain)
            if existing is None or existing[0] < ts:
                docs[domain] = (ts, d)
        for r in b.revocations:
            existing = revs.get(r.domain)
            if existing is None or existing[0] < ts:
                revs[r.domain] = (ts, r)

    documents = [v[1] for v in docs.values()]
    documents.sort(key=lambda d: d.get("domain", ""))
    revocations = [v[1] for v in revs.values()]
    revocations.sort(key=lambda r: r.domain)

    return SchemaPinTrustBundle(
        schemapin_bundle_version=BUNDLE_VERSION_SIGNED,
        created_at=newest_ts,
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
