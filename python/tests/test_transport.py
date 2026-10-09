"""Tests for the hardened HTTP transport (SP-11)."""

from unittest.mock import MagicMock, patch

import pytest

from schemapin.discovery import PublicKeyDiscovery
from schemapin.transport import (
    MAX_RESPONSE_BYTES,
    TransportError,
    fetch_json,
    require_https,
)


def _response(status=200, chunks=(b'{"ok":true}',)):
    resp = MagicMock()
    resp.status_code = status
    resp.iter_content = lambda chunk_size: iter(chunks)
    return resp


def test_https_required():
    with pytest.raises(TransportError):
        require_https("http://example.com/.well-known/schemapin.json")
    with pytest.raises(TransportError):
        require_https("ftp://example.com/x")
    with pytest.raises(TransportError):
        require_https("https://user:pw@example.com/x")
    assert require_https("https://example.com/x") == "https://example.com/x"
    with pytest.raises(TransportError):
        fetch_json("http://example.com/x")


def test_redirects_are_not_followed():
    with patch("schemapin.transport.requests.get", return_value=_response(302)) as get:
        with pytest.raises(TransportError, match="redirect"):
            fetch_json("https://example.com/x")
        assert get.call_args.kwargs["allow_redirects"] is False


def test_body_size_cap():
    big = b"x" * (MAX_RESPONSE_BYTES + 1)
    with patch("schemapin.transport.requests.get", return_value=_response(200, (big,))):
        with pytest.raises(TransportError, match="exceeds"):
            fetch_json("https://example.com/x")


def test_success_path_parses_json():
    with patch("schemapin.transport.requests.get", return_value=_response()):
        assert fetch_json("https://example.com/x") == {"ok": True}


def test_well_known_url_rejects_http_and_validates_domain():
    with pytest.raises(ValueError):
        PublicKeyDiscovery.construct_well_known_url("http://example.com")
    with pytest.raises(ValueError):
        PublicKeyDiscovery.construct_well_known_url("example.com/evil")
    with pytest.raises(ValueError):
        PublicKeyDiscovery.construct_well_known_url("localhost")
    assert (
        PublicKeyDiscovery.construct_well_known_url("Example.com")
        == "https://example.com/.well-known/schemapin.json"
    )
    assert (
        PublicKeyDiscovery.construct_well_known_url("https://example.com")
        == "https://example.com/.well-known/schemapin.json"
    )
