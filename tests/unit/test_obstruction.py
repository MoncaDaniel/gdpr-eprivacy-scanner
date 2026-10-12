"""Bot-challenge and error-page recognition (risk R3, ADR-0010)."""

from __future__ import annotations

import pytest

from privacy_scanner.collector.obstruction import detect_obstruction
from privacy_scanner.domain.evidence import ObstructionKind


@pytest.mark.parametrize(
    ("status", "headers", "title", "html", "provider"),
    [
        (403, {"cf-mitigated": "challenge"}, "", "", "Cloudflare"),
        (503, {}, "Just a moment...", "", "Cloudflare"),
        (403, {}, "Un instant…", "", "Cloudflare"),
        (
            403,
            {},
            "",
            '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js">',
            "Cloudflare",
        ),
        (403, {"x-datadome": "protected"}, "", "", "DataDome"),
        (403, {}, "", '<iframe src="https://geo.captcha-delivery.com/captcha/">', "DataDome"),
        (403, {}, "", '<div id="px-captcha"></div>', "HUMAN (PerimeterX)"),
        (200, {}, "", "Request unsuccessful. Incapsula incident ID: 123", "Imperva"),
        (403, {}, "", '<script src="/_Incapsula_Resource?SWJIYLWA=1">', "Imperva"),
        (403, {"server": "AkamaiGHost"}, "Access Denied", "", "Akamai"),
    ],
)
def test_known_challenges_are_recognised(
    status: int, headers: dict[str, str], title: str, html: str, provider: str
) -> None:
    obstruction = detect_obstruction(
        status=status, headers={k.lower(): v for k, v in headers.items()}, title=title, html=html
    )
    assert obstruction is not None
    assert obstruction.kind is ObstructionKind.BOT_CHALLENGE
    assert obstruction.provider == provider


@pytest.mark.parametrize(
    ("title", "html", "headers"),
    [
        # A real login page with an embedded Turnstile widget.
        ("Connexion", '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js">', {}),
        # A French page whose title happens to start like a challenge title.
        ("Un instant de bonheur — recettes", "<h1>Recettes</h1>", {}),
        # Imperva-fronted site: the resource script is on every page.
        ("Accueil", '<script src="/_Incapsula_Resource?SWJIYLWA=1">', {}),
        # Served through Akamai, but not blocked.
        ("Access Denied (a band)", "", {"server": "AkamaiGHost"}),
        ("Home", "<p>Protected by DataDome</p>", {"x-datadome": "protected"}),
    ],
)
def test_ordinary_pages_from_protected_sites_are_not_obstructions(
    title: str, html: str, headers: dict[str, str]
) -> None:
    assert detect_obstruction(status=200, headers=headers, title=title, html=html) is None


@pytest.mark.parametrize("status", [404, 410, 500, 502])
def test_error_statuses_without_a_signature_are_http_errors(status: int) -> None:
    obstruction = detect_obstruction(status=status, headers={}, title="Oops", html="")
    assert obstruction is not None
    assert obstruction.kind is ObstructionKind.HTTP_ERROR
    assert str(status) in obstruction.detail


def test_unknown_status_is_not_an_obstruction() -> None:
    assert detect_obstruction(status=None, headers={}, title=None, html="") is None
