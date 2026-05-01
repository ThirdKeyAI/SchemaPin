"""DNS TXT cross-verification for SchemaPin v1.4.

A tool provider MAY publish a TXT record at ``_schemapin.{domain}`` containing
the public-key fingerprint advertised in ``.well-known/schemapin.json``. When
present, clients use it as a *second-channel* verification: the DNS
credential chain is independent of the HTTPS hosting credential chain, so
compromising one does not compromise the other.

TXT record format::

    _schemapin.example.com. IN TXT "v=schemapin1; kid=acme-2026-01; fp=sha256:a1b2c3..."

Fields:

- ``v`` -- version tag (``schemapin1``); required
- ``fp`` -- key fingerprint (``sha256:<hex>``); required, lowercase hex
- ``kid`` -- optional key id, used for disambiguating multi-key endpoints

Verification semantics:

- **Absent record** -- no effect (DNS TXT is optional)
- **Present and matching** -- confidence boost (no warning emitted; absence
  of mismatch is the signal)
- **Present and mismatching** -- hard failure with
  :class:`schemapin.verification.ErrorCode.DOMAIN_MISMATCH`

Use :func:`parse_txt_record` to parse a raw TXT string and
:func:`verify_dns_match` to cross-check it against a discovery document.
:func:`fetch_dns_txt` performs the DNS lookup; it requires the optional
``dnspython`` dependency (``pip install schemapin[dns]``).
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional

from .crypto import KeyManager


@dataclass
class DnsTxtRecord:
    """Parsed ``_schemapin.{domain}`` TXT record.

    ``fingerprint`` is the lowercase string including the ``sha256:`` prefix
    so it can be compared directly with
    :meth:`KeyManager.calculate_key_fingerprint` output.
    """

    version: str
    fingerprint: str
    kid: Optional[str] = None


def parse_txt_record(value: str) -> DnsTxtRecord:
    """Parse a raw TXT record value.

    Example input::

        v=schemapin1; kid=acme-2026-01; fp=sha256:a1b2c3...

    Whitespace around ``;`` and ``=`` is tolerated. Field order is not
    significant. Unknown fields are ignored (forward-compat).

    Raises:
        ValueError: When the record is missing the required ``v`` or ``fp``
            fields, when the version is not ``schemapin1``, when ``fp`` lacks
            the ``sha256:`` prefix, or when a field is missing ``=``.
    """
    version: Optional[str] = None
    kid: Optional[str] = None
    fp: Optional[str] = None

    for raw_part in value.split(";"):
        part = raw_part.strip()
        if not part:
            continue
        if "=" not in part:
            raise ValueError(f"DNS TXT field missing '=': {part}")
        k, v = part.split("=", 1)
        k = k.strip().lower()
        v = v.strip()
        if k == "v":
            version = v
        elif k == "kid":
            kid = v
        elif k == "fp":
            fp = v.lower()
        # Forward-compat: ignore unknown fields rather than reject.

    if version is None:
        raise ValueError("DNS TXT record missing required 'v' field")
    if version != "schemapin1":
        raise ValueError(f"DNS TXT unsupported version: {version}")
    if fp is None:
        raise ValueError("DNS TXT record missing required 'fp' field")
    if not fp.startswith("sha256:"):
        raise ValueError(f"DNS TXT 'fp' must be sha256:<hex>: {fp}")

    return DnsTxtRecord(version=version, kid=kid, fingerprint=fp)


def verify_dns_match(
    discovery: Dict[str, Any], txt: DnsTxtRecord
) -> None:
    """Cross-check the DNS TXT record's fingerprint against the discovery doc.

    Computes the SHA-256 fingerprint of ``discovery["public_key_pem"]`` and
    compares it (case-insensitively) with ``txt.fingerprint``.

    Raises:
        ValueError: When the discovery document lacks ``public_key_pem`` or
            the fingerprints do not match. The mismatch case is what callers
            should map to ``ErrorCode.DOMAIN_MISMATCH``.
    """
    public_key_pem = discovery.get("public_key_pem")
    if not public_key_pem:
        raise ValueError(
            "Discovery document missing 'public_key_pem'; cannot compute fingerprint"
        )
    computed = KeyManager.calculate_key_fingerprint_from_pem(public_key_pem).lower()
    if computed != txt.fingerprint:
        raise ValueError(
            f"DNS TXT fingerprint mismatch: discovery={computed}, dns={txt.fingerprint}"
        )


def txt_record_name(domain: str) -> str:
    """Construct the DNS lookup name for a given tool domain."""
    return f"_schemapin.{domain.rstrip('.')}"


def fetch_dns_txt(domain: str) -> Optional[DnsTxtRecord]:
    """Fetch and parse the ``_schemapin.{domain}`` TXT record.

    Requires the optional ``dnspython`` dependency. Install with::

        pip install schemapin[dns]
        # or
        pip install dnspython

    Returns:
        The parsed record when present, or ``None`` when no
        ``_schemapin.{domain}`` TXT record exists.

    Multiple matching TXT chunks are joined per RFC 1464 (concatenation in
    emit order). Multiple separate TXT records at the same name are not
    supported -- the first record containing ``v=schemapin1`` wins.

    Raises:
        ImportError: When ``dnspython`` is not installed.
        ValueError: When the record exists but is malformed.
        RuntimeError: For DNS resolution errors other than NXDOMAIN/NoAnswer.
    """
    try:
        import dns.exception
        import dns.resolver
    except ImportError as e:
        raise ImportError(
            "fetch_dns_txt requires the 'dnspython' package; "
            "install schemapin[dns] or pip install dnspython"
        ) from e

    name = txt_record_name(domain)
    try:
        answer = dns.resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None
    except dns.exception.DNSException as e:
        raise RuntimeError(f"DNS TXT lookup failed for {name}: {e}") from e

    for record in answer:
        # dnspython exposes TXT chunks via .strings (list of bytes) per RFC 1464.
        chunks = getattr(record, "strings", None) or []
        try:
            joined = "".join(
                c.decode("utf-8", errors="replace") if isinstance(c, (bytes, bytearray)) else str(c)
                for c in chunks
            )
        except Exception:
            joined = str(record)
        if "v=schemapin1" in joined:
            return parse_txt_record(joined)
    return None
