"""Builders for Evidence Bundles in pure unit tests (no browser).

Defaults describe a completed S0 session on https://www.example.fr/ with
nothing stored and nothing contacted; tests add exactly what they need.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from privacy_scanner.domain.evidence import (
    BlockReason,
    Box,
    BrowserEnvironment,
    CookieRecord,
    EvidenceBundle,
    FrameUi,
    NavigationRecord,
    Obstruction,
    ObstructionKind,
    RequestRecord,
    ScanTarget,
    SessionEvidence,
    SessionKind,
    SessionOutcome,
    StorageArea,
    StorageRecord,
    UiControl,
    UiLayer,
    UiLayerKind,
    ValueFingerprint,
    Viewport,
)

PAGE = "https://www.example.fr/"
T0 = datetime(2026, 10, 16, 9, 0, tzinfo=UTC)
FP = ValueFingerprint(length=12, digest="0123456789abcdef")
DAY = 86_400


def cookie(
    name: str,
    domain: str = "www.example.fr",
    *,
    lifetime_s: int | None = 30 * DAY,
    first_ms: int = 300,
) -> CookieRecord:
    return CookieRecord(
        name=name,
        domain=domain,
        path="/",
        value=FP,
        expires_at=None if lifetime_s is None else T0 + timedelta(seconds=lifetime_s),
        lifetime_seconds=lifetime_s,
        http_only=False,
        secure=True,
        same_site=None,
        first_observed_ms=first_ms,
    )


_seq = iter(range(1_000_000))


def request(
    url: str,
    *,
    resource_type: str = "script",
    method: str = "GET",
    started_ms: int = 100,
    blocked: bool = False,
) -> RequestRecord:
    return RequestRecord(
        sequence=next(_seq),
        url=url,
        method=method,
        resource_type=resource_type,
        started_ms=started_ms,
        frame_url=PAGE,
        is_navigation=False,
        status=None if blocked else 200,
        blocked_by=BlockReason.NON_PUBLIC_ADDRESS if blocked else None,
    )


def storage(key: str, origin: str = "https://www.example.fr", length: int = 36) -> StorageRecord:
    return StorageRecord(
        origin=origin,
        area=StorageArea.LOCAL,
        key=key,
        value=ValueFingerprint(length=length, digest="fedcba9876543210"),
    )


def box(x: float = 100, y: float = 700, w: float = 120, h: float = 36) -> Box:
    return Box(x=x, y=y, width=w, height=h)


def control(
    label: str, layer_id: int = 0, *, in_viewport: bool = True, aria: str | None = None
) -> UiControl:
    return UiControl(
        layer_id=layer_id,
        tag="button",
        role=None,
        label=label,
        aria_label=aria,
        box=box(),
        in_viewport=in_viewport,
        font_size_px=14.0,
        font_weight=600,
        color="rgb(255, 255, 255)",
        background_color="rgb(31, 58, 95)",
        in_shadow_root=False,
    )


def layer(
    text: str,
    layer_id: int = 0,
    *,
    element: str = "div#banner",
    kind: UiLayerKind = UiLayerKind.FIXED,
) -> UiLayer:
    return UiLayer(
        layer_id=layer_id,
        kind=kind,
        element=element,
        box=Box(x=0, y=600, width=1366, height=168),
        z_index=1000,
        text=text,
    )


def frame_ui(
    layers: tuple[UiLayer, ...] = (),
    controls: tuple[UiControl, ...] = (),
    *,
    frame_index: int = 0,
    url: str = PAGE,
    is_main: bool = True,
) -> FrameUi:
    return FrameUi(
        frame_index=frame_index,
        frame_url=url,
        is_main=is_main,
        viewport=Viewport(width=1366, height=768),
        layers=layers,
        controls=controls,
    )


def banner(
    *labels: str, text: str = "Nous utilisons des cookies.", element: str = "div#banner"
) -> tuple[FrameUi, ...]:
    """A single fixed banner layer with one control per label."""
    return (frame_ui((layer(text, element=element),), tuple(control(lbl) for lbl in labels)),)


def session(
    *,
    cookies: tuple[CookieRecord, ...] = (),
    requests: tuple[RequestRecord, ...] = (),
    storage_items: tuple[StorageRecord, ...] = (),
    consent_ui: tuple[FrameUi, ...] | None = (),
    outcome: SessionOutcome = SessionOutcome.COMPLETED,
    final_url: str = PAGE,
    kind: SessionKind = SessionKind.BASELINE,
) -> SessionEvidence:
    obstruction = (
        Obstruction(kind=ObstructionKind.BOT_CHALLENGE, detail="Cloudflare challenge")
        if outcome is SessionOutcome.OBSTRUCTED
        else None
    )
    return SessionEvidence(
        kind=kind,
        outcome=outcome,
        started_at=T0,
        duration_ms=9000,
        observation_window_ms=6000,
        error=obstruction.detail if obstruction else None,
        navigation=NavigationRecord(
            requested_url=PAGE, final_url=final_url, status=200, page_title="Example"
        ),
        obstruction=obstruction,
        cookies=cookies,
        requests=requests,
        storage=storage_items,
        consent_ui=consent_ui,
    )


def environment() -> BrowserEnvironment:
    return BrowserEnvironment(
        engine="chromium",
        engine_version="140.0",
        user_agent="Mozilla/5.0 test",
        viewport=Viewport(width=1366, height=768),
        locale="fr-FR",
        timezone="Europe/Paris",
        accept_language="fr-FR,fr;q=0.9",
        headless=True,
        vantage_point="test",
    )


def bundle(*sessions: SessionEvidence, **session_kwargs: object) -> EvidenceBundle:
    if not sessions:
        sessions = (session(**session_kwargs),)  # type: ignore[arg-type]
    return EvidenceBundle(
        scan_id="0" * 32,
        scanner_version="0.0.0-test",
        created_at=T0,
        target=ScanTarget(input_url="example.fr", normalized_url=PAGE),
        environment=environment(),
        sessions=sessions,
    )
