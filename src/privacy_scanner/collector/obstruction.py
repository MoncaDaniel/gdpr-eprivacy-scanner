"""Recognise bot-protection challenges and error pages (risk R3).

A challenge page is not the site: analysing it would produce a fabricated
result. We detect it and say so; we never try to defeat it (ADR-0010).
Detection is pure so every signature has a unit test.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from privacy_scanner.domain.evidence import Obstruction, ObstructionKind


@dataclass(frozen=True, slots=True)
class _Signature:
    provider: str
    title_markers: tuple[str, ...] = ()
    body_markers: tuple[str, ...] = ()
    header_markers: tuple[tuple[str, str], ...] = ()
    """(header name, substring of value); empty value matches presence."""
    statuses: frozenset[int] | None = None
    """If set, the signature only applies to these HTTP statuses."""


_SIGNATURES: tuple[_Signature, ...] = (
    _Signature(
        provider="Cloudflare",
        title_markers=("just a moment", "attention required! | cloudflare", "un instant"),
        body_markers=("challenges.cloudflare.com/turnstile", "_cf_chl_opt", "cf-chl-"),
        header_markers=(("cf-mitigated", "challenge"),),
        # Turnstile widgets are embedded in ordinary 200 pages (login forms):
        # only an error status makes the marker mean "challenge instead of site".
        statuses=frozenset({403, 429, 503}),
    ),
    _Signature(
        provider="DataDome",
        body_markers=("captcha-delivery.com", "geo.captcha-delivery"),
        header_markers=(("x-datadome", ""),),
        statuses=frozenset({401, 403, 405, 429}),
    ),
    _Signature(
        provider="HUMAN (PerimeterX)",
        body_markers=("px-captcha", "_pxcaptcha", "perimeterx"),
        statuses=frozenset({403, 429}),
    ),
    _Signature(
        # The block page is unambiguous at any status.
        provider="Imperva",
        body_markers=("incapsula incident id",),
    ),
    _Signature(
        # The resource script is injected into normal pages too; only an error
        # status makes it a challenge.
        provider="Imperva",
        body_markers=("_incapsula_resource",),
        statuses=frozenset({401, 403, 429}),
    ),
    _Signature(
        provider="Akamai",
        title_markers=("access denied",),
        header_markers=(("server", "akamaighost"),),
        statuses=frozenset({403}),
    ),
)


def detect_obstruction(
    *,
    status: int | None,
    headers: Mapping[str, str],
    title: str | None,
    html: str,
) -> Obstruction | None:
    """Return an ``Obstruction`` if the main document is not the real page.

    ``headers`` keys must be lower-case (Playwright's ``all_headers()`` is).
    ``html`` may be a prefix of the document.
    """
    title_lc = (title or "").strip().lower()
    body_lc = html.lower()

    for sig in _SIGNATURES:
        if sig.statuses is not None and status not in sig.statuses:
            continue
        hit = (
            any(title_lc.startswith(m) for m in sig.title_markers)
            or any(m in body_lc for m in sig.body_markers)
            or any(
                name in headers and value in headers[name].lower()
                for name, value in sig.header_markers
            )
        )
        if hit:
            return Obstruction(
                kind=ObstructionKind.BOT_CHALLENGE,
                provider=sig.provider,
                detail=f"{sig.provider} bot-protection page served instead of the site"
                + (f" (HTTP {status})" if status else ""),
            )

    if status is not None and status >= 400:
        return Obstruction(
            kind=ObstructionKind.HTTP_ERROR, detail=f"Main document returned HTTP {status}"
        )
    return None
