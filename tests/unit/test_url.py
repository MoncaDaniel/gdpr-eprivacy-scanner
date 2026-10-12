"""URL intake: what the guard checks must be what Chromium loads."""

from __future__ import annotations

import pytest

from privacy_scanner.intake.url import InvalidUrlError, canonical_host, normalize_url


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "https://example.com/"),
        ("  HTTPS://Example.COM/a?b=1#frag ", "https://example.com/a?b=1"),
        ("http://example.com:80/", "http://example.com/"),
        ("https://example.com:8443", "https://example.com:8443/"),
        ("https://bücher.de/", "https://xn--bcher-kva.de/"),
        ("https://example.com./", "https://example.com/"),
        ("http://[::FFFF:7f00:1]/", "http://[::ffff:127.0.0.1]/"),  # same address, Python spelling
    ],
)
def test_normalize_url_canonicalises(raw: str, expected: str) -> None:
    assert normalize_url(raw).url == expected


@pytest.mark.parametrize(
    ("spelling", "canonical"),
    [
        ("2130706433", "127.0.0.1"),
        ("0x7f.1", "127.0.0.1"),
        ("127.1", "127.0.0.1"),
        ("0177.0.0.1", "127.0.0.1"),
        ("0xa9fea9fe", "169.254.169.254"),
        ("169.254.43518", "169.254.169.254"),
    ],
)
def test_legacy_ipv4_spellings_are_canonicalised_like_browsers(
    spelling: str, canonical: str
) -> None:
    assert canonical_host(spelling) == canonical
    assert normalize_url(f"http://{spelling}/").host == canonical


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "ftp://example.com/",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "https://user:pass@example.com/",
        "https://exa mple.com/",
        "https://example.com/\x00",
        "https://" + "a" * 2100 + ".com/",
        "https://-bad-.com/",
        "https://1.2.3.4.5/",
        "https://[::g]/",
    ],
)
def test_normalize_url_rejects_unscannable_input(raw: str) -> None:
    with pytest.raises(InvalidUrlError):
        normalize_url(raw)
