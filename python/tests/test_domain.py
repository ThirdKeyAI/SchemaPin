"""Tests for the shared domain validator (SP-11 / SP-16)."""

import pytest

from schemapin.domain import InvalidDomainError, is_valid_domain, validate_domain


@pytest.mark.parametrize(
    "domain,expected",
    [
        ("example.com", "example.com"),
        ("Example.COM", "example.com"),
        ("sub.domain.example.co.uk", "sub.domain.example.co.uk"),
        ("xn--bcher-kva.example", "xn--bcher-kva.example"),
        ("a-b.c1", "a-b.c1"),
        ("1.example", "1.example"),
    ],
)
def test_valid_domains(domain, expected):
    assert validate_domain(domain) == expected
    assert is_valid_domain(domain)


@pytest.mark.parametrize(
    "domain",
    [
        "",
        "localhost",
        "example",
        "http://example.com",
        "https://example.com",
        "example.com/path",
        "example.com:8443",
        "user@example.com",
        "good.com@evil.com",
        "../skills/evil/key",
        "/etc/passwd",
        "example.com.",
        ".example.com",
        "exa mple.com",
        "-bad.example.com",
        "bad-.example.com",
        "under_score.example.com",
        "10.0.0.1",
        "[::1]",
        "bücher.example",
        "a" * 64 + ".example.com",
        ("a" * 63 + ".") * 4 + "com",
        "evil.com\nexample.com",
    ],
)
def test_invalid_domains(domain):
    with pytest.raises(InvalidDomainError):
        validate_domain(domain)
    assert not is_valid_domain(domain)


def test_non_string_rejected():
    with pytest.raises(InvalidDomainError):
        validate_domain(None)  # type: ignore[arg-type]
