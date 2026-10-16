"""Browser sessions. Phase 1 implements S0 (baseline, no interaction).

S0 protocol (ADR-0010)
----------------------
1. Fresh isolated context whose only network exit is a dedicated
   ``EgressProxy`` (ADR-0011); guard routing and recorders installed *before*
   the first request.
2. Navigate; wait for ``load`` and then, best effort, network idle.
3. Observe for ``observation_window_s`` without any interaction: no clicks,
   no scrolling, no mouse movement, no key presses. Scrolling is excluded on
   purpose: some consent platforms treat scrolling as consent, which would
   contaminate the "before consent" baseline.
4. Capture cookie jar, Web Storage, DOM, the consent-UI snapshot (visible
   overlay layers and their controls, ADR-0012) and a viewport screenshot.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass
from datetime import UTC, datetime

from playwright.async_api import Browser, BrowserContext, Error, Page, Response
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from privacy_scanner.collector.artifacts import ArtifactStore
from privacy_scanner.collector.browser import new_isolated_context
from privacy_scanner.collector.capture import (
    capture_consent_ui,
    capture_frames,
    capture_screenshot,
    capture_storage,
    main_document_html,
)
from privacy_scanner.collector.clock import SessionClock
from privacy_scanner.collector.cookies import CookieJarObserver
from privacy_scanner.collector.egress import EgressProxy
from privacy_scanner.collector.fingerprint import ValueFingerprinter
from privacy_scanner.collector.network import NetworkRecorder
from privacy_scanner.collector.obstruction import detect_obstruction
from privacy_scanner.config import ScannerSettings
from privacy_scanner.domain.evidence import (
    BrowserEnvironment,
    NavigationRecord,
    Obstruction,
    SessionEvidence,
    SessionKind,
    SessionOutcome,
)
from privacy_scanner.intake.ssrf_guard import SsrfGuard

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class SessionDeps:
    browser: Browser
    environment: BrowserEnvironment
    settings: ScannerSettings
    guard: SsrfGuard
    store: ArtifactStore
    fingerprinter: ValueFingerprinter


@dataclass(slots=True)
class _NavigationOutcome:
    response: Response | None = None
    error: str | None = None
    dom_content_loaded_ms: int | None = None
    load_ms: int | None = None
    network_idle: bool = False


async def run_baseline_session(url: str, deps: SessionDeps) -> SessionEvidence:
    """Run S0 against ``url`` (already normalised and pre-flight checked)."""
    started_at = datetime.now(UTC)
    clock = SessionClock()

    async with EgressProxy(deps.guard, clock) as proxy:
        context = await new_isolated_context(
            deps.browser, deps.environment, proxy_server=proxy.server_url
        )
        try:
            return await _observe(
                context, url, deps, clock=clock, proxy=proxy, started_at=started_at
            )
        finally:
            with contextlib.suppress(Error):
                await context.close()


async def _observe(
    context: BrowserContext,
    url: str,
    deps: SessionDeps,
    *,
    clock: SessionClock,
    proxy: EgressProxy,
    started_at: datetime,
) -> SessionEvidence:
    kind = SessionKind.BASELINE
    prefix = kind.value.lower()
    settings = deps.settings
    recorder = NetworkRecorder(
        guard=deps.guard,
        clock=clock,
        egress=proxy.log,
        max_requests=settings.max_requests_per_session,
    )
    await recorder.install(context)
    jar = CookieJarObserver(context, clock, settings.cookie_poll_interval_s)
    page = await context.new_page()

    stop = asyncio.Event()
    clock.reset()
    poller = asyncio.create_task(jar.run(stop))
    try:
        nav = await _navigate(page, url, clock, settings)
        if nav.error is None:
            await asyncio.sleep(settings.observation_window_s)
    finally:
        stop.set()
        await poller
    observation_end_ms = clock.now_ms()
    await jar.poll_once()

    blocked = recorder.blocked_navigation()
    if nav.error is not None:
        outcome = SessionOutcome.BLOCKED if blocked is not None else SessionOutcome.FAILED
        failure = (
            f"Navigation blocked by network policy: {blocked.detail}" if blocked else nav.error
        )
        return SessionEvidence(
            kind=kind,
            outcome=outcome,
            started_at=started_at,
            duration_ms=clock.now_ms(),
            observation_window_ms=0,
            error=failure,
            cookies=jar.records(datetime.now(UTC), deps.fingerprinter),
            requests=recorder.records(),
            requests_dropped=recorder.dropped,
            guard_violations=recorder.violations,
        )

    navigation = await _navigation_record(page, url, nav)
    obstruction = await _obstruction(page, nav.response, navigation)
    storage = await capture_storage(page, deps.fingerprinter)
    frames = await capture_frames(
        page,
        deps.store,
        prefix,
        max_frames=settings.max_frames,
        max_dom_bytes=settings.max_dom_bytes,
    )
    consent_ui = await capture_consent_ui(page, max_frames=settings.max_frames)
    screenshot = await capture_screenshot(page, deps.store, prefix)

    violations = recorder.violations
    error: str | None
    if violations:
        outcome, error = SessionOutcome.BLOCKED, "Response received from a non-public address"
    elif obstruction is not None:
        outcome, error = SessionOutcome.OBSTRUCTED, obstruction.detail
    else:
        outcome, error = SessionOutcome.COMPLETED, None

    return SessionEvidence(
        kind=kind,
        outcome=outcome,
        started_at=started_at,
        duration_ms=clock.now_ms(),
        observation_window_ms=max(
            0, observation_end_ms - (nav.load_ms or nav.dom_content_loaded_ms or 0)
        ),
        error=error,
        navigation=navigation,
        obstruction=obstruction,
        cookies=jar.records(datetime.now(UTC), deps.fingerprinter),
        requests=recorder.records(),
        requests_dropped=recorder.dropped,
        storage=storage,
        frames=frames,
        screenshot=screenshot,
        guard_violations=violations,
        consent_ui=consent_ui,
    )


async def _navigate(
    page: Page, url: str, clock: SessionClock, settings: ScannerSettings
) -> _NavigationOutcome:
    nav = _NavigationOutcome()
    timeout_ms = settings.navigation_timeout_s * 1000
    try:
        nav.response = await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
    except PlaywrightTimeoutError:
        nav.error = f"Navigation timed out after {settings.navigation_timeout_s:g}s"
        return nav
    except Error as exc:
        nav.error = f"Navigation failed: {exc.message.splitlines()[0]}"
        return nav
    nav.dom_content_loaded_ms = clock.now_ms()

    try:
        await page.wait_for_load_state("load", timeout=timeout_ms)
        nav.load_ms = clock.now_ms()
    except (PlaywrightTimeoutError, Error):
        logger.info("load event not reached for %s; continuing with partial page", url)

    if settings.network_idle_timeout_s > 0:
        try:
            await page.wait_for_load_state(
                "networkidle", timeout=settings.network_idle_timeout_s * 1000
            )
            nav.network_idle = True
        except (PlaywrightTimeoutError, Error):
            logger.info("network idle not reached for %s (long-polling or beacons)", url)
    return nav


async def _navigation_record(page: Page, url: str, nav: _NavigationOutcome) -> NavigationRecord:
    chain: list[str] = []
    status: int | None = None
    if nav.response is not None:
        status = nav.response.status
        hop = nav.response.request.redirected_from
        while hop is not None:
            chain.append(hop.url)
            hop = hop.redirected_from
        chain.reverse()
    title: str | None
    try:
        title = await page.title()
    except Error:
        title = None
    return NavigationRecord(
        requested_url=url,
        final_url=page.url,
        status=status,
        redirect_chain=tuple(chain),
        page_title=title or None,
        dom_content_loaded_ms=nav.dom_content_loaded_ms,
        load_ms=nav.load_ms,
        network_idle_reached=nav.network_idle,
    )


async def _obstruction(
    page: Page, response: Response | None, navigation: NavigationRecord
) -> Obstruction | None:
    headers: dict[str, str] = {}
    if response is not None:
        with contextlib.suppress(Error):
            headers = await response.all_headers()
    return detect_obstruction(
        status=navigation.status,
        headers=headers,
        title=navigation.page_title,
        html=await main_document_html(page),
    )
