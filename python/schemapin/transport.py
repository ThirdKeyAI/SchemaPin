"""Hardened HTTP fetch helpers shared by discovery and revocation.

Every outbound request made by this package goes through :func:`fetch_json`:

* ``https://`` only -- plaintext URLs are refused before any socket is opened
* redirects are never followed (a 3xx response is a failure)
* the response body is capped at :data:`MAX_RESPONSE_BYTES`
* a connect/read timeout is always applied
"""

from typing import Any
from urllib.parse import urlsplit

import requests

#: Maximum accepted response body size (bytes).
MAX_RESPONSE_BYTES = 64 * 1024

#: Default timeout in seconds.
DEFAULT_TIMEOUT = 10


class TransportError(RuntimeError):
    """Raised for any transport-level failure (scheme, redirect, size, network)."""


def require_https(url: str) -> str:
    """Return ``url`` unchanged if it is an absolute ``https://`` URL."""
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.netloc:
        raise TransportError(f"only https:// URLs are permitted: {url!r}")
    if "@" in parts.netloc:
        raise TransportError(f"userinfo is not permitted in URLs: {url!r}")
    return url


def fetch_json(
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
    max_bytes: int = MAX_RESPONSE_BYTES,
) -> Any:
    """GET ``url`` and decode the JSON body under the hardening rules above.

    Raises:
        TransportError: on a non-https URL, a redirect, a non-200 status, an
            oversized body, a network error or undecodable JSON.
    """
    import json

    require_https(url)
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            stream=True,
            headers={"Accept": "application/json", "User-Agent": "SchemaPin"},
        )
    except requests.RequestException as e:
        raise TransportError(f"request failed for {url}: {e}") from e
    try:
        if 300 <= resp.status_code < 400:
            raise TransportError(
                f"redirect ({resp.status_code}) fetching {url}; redirects are not followed"
            )
        if resp.status_code != 200:
            raise TransportError(f"HTTP {resp.status_code} fetching {url}")
        body = b""
        for chunk in resp.iter_content(chunk_size=8192):
            body += chunk
            if len(body) > max_bytes:
                raise TransportError(
                    f"response from {url} exceeds {max_bytes} bytes"
                )
    finally:
        resp.close()
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise TransportError(f"invalid JSON from {url}: {e}") from e
