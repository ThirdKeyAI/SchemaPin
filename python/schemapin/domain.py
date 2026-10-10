"""Shared domain-name validation.

Every place that turns a domain string into something security-relevant --
a ``.well-known`` URL, a pin-store key, a local file path, a DNS lookup name
-- MUST pass it through :func:`validate_domain` first. The grammar is the
RFC 1123 hostname grammar, restricted further so that the value cannot be
confused with a URL, a path, an IP literal or an IDN U-label:

* ASCII only (internationalized names must be given as punycode A-labels)
* at least two labels, each 1-63 characters of ``[a-z0-9-]`` that neither
  start nor end with ``-``
* total length at most 253 characters
* the last label is not purely numeric (rejects IPv4 literals)
* no scheme, path, port, userinfo or trailing dot

The returned value is lowercased so that pin keys and file names are
consistent regardless of how the caller spelled the domain.
"""

import re

#: Maximum total length of a domain name.
MAX_DOMAIN_LENGTH = 253

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class InvalidDomainError(ValueError):
    """Raised when a string is not an acceptable SchemaPin domain."""


def validate_domain(domain: str) -> str:
    """Validate ``domain`` and return its normalized (lowercase) form.

    Raises:
        InvalidDomainError: if the value is not a bare RFC 1123 hostname with
            at least two labels.
    """
    if not isinstance(domain, str) or not domain:
        raise InvalidDomainError("domain must be a non-empty string")
    if len(domain) > MAX_DOMAIN_LENGTH:
        raise InvalidDomainError(f"domain exceeds {MAX_DOMAIN_LENGTH} characters")
    if not domain.isascii():
        raise InvalidDomainError(
            "domain must be ASCII; encode internationalized names as punycode"
        )
    normalized = domain.lower()
    labels = normalized.split(".")
    if len(labels) < 2:
        raise InvalidDomainError(f"domain {domain!r} must contain at least two labels")
    for label in labels:
        if not _LABEL_RE.match(label):
            raise InvalidDomainError(
                f"domain {domain!r} has an invalid label {label!r}"
            )
    if labels[-1].isdigit():
        raise InvalidDomainError(f"domain {domain!r} looks like an IP literal")
    return normalized


def is_valid_domain(domain: str) -> bool:
    """Return ``True`` when :func:`validate_domain` would accept ``domain``."""
    try:
        validate_domain(domain)
    except InvalidDomainError:
        return False
    return True
