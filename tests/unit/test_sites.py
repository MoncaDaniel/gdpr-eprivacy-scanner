"""Site (eTLD+1) semantics: the technical basis of first- vs third-party."""

from __future__ import annotations

import pytest

from privacy_scanner.domain.sites import cookie_host, registrable_domain, same_site


@pytest.mark.parametrize(
    ("host", "site"),
    [
        ("www.example.com", "example.com"),
        ("a.b.example.co.uk", "example.co.uk"),
        ("WWW.Example.FR.", "example.fr"),
        ("alice.github.io", "alice.github.io"),  # PSL private section, as browsers use it
        ("93.184.215.14", "93.184.215.14"),
        ("[2606:4700::1]", "2606:4700::1"),
        ("co.uk", "co.uk"),
    ],
)
def test_registrable_domain(host: str, site: str) -> None:
    assert registrable_domain(host) == site


def test_same_site_follows_registrable_domain() -> None:
    assert same_site("www.lemonde.fr", "static.lemonde.fr")
    assert not same_site("alice.github.io", "bob.github.io")
    assert not same_site("lemonde.fr", "google-analytics.com")


def test_cookie_host_strips_leading_dot() -> None:
    assert cookie_host(".Example.com") == "example.com"
