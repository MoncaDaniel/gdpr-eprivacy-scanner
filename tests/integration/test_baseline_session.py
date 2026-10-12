"""S0 baseline against hermetic fixture sites: what the collector must observe."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from privacy_scanner.collector.service import BUNDLE_FILENAME, collect
from privacy_scanner.collector.summary import digest
from privacy_scanner.config import ScannerSettings
from privacy_scanner.domain.evidence import (
    BlockReason,
    EvidenceBundle,
    ObstructionKind,
    SessionEvidence,
    SessionKind,
    SessionOutcome,
    StorageArea,
)
from privacy_scanner.intake.ssrf_guard import SsrfGuard
from tests.fixtures.server import FixtureSites

pytestmark = pytest.mark.integration

CHROMIUM_MAX_COOKIE_LIFETIME_S = 400 * 24 * 3600


async def _baseline(
    url: str, settings: ScannerSettings, guard: SsrfGuard
) -> tuple[EvidenceBundle, SessionEvidence, Path]:
    result = await collect(url, settings, guard=guard)
    session = result.bundle.session(SessionKind.BASELINE)
    assert session is not None
    return result.bundle, session, result.directory


async def test_clean_site_stores_nothing_and_contacts_only_itself(
    sites: FixtureSites, settings: ScannerSettings, guard: SsrfGuard
) -> None:
    _, s0, _ = await _baseline(sites.url("clean.html"), settings, guard)

    assert s0.outcome is SessionOutcome.COMPLETED
    assert s0.cookies == ()
    assert s0.storage == ()
    assert {urlsplit(r.url).hostname for r in s0.requests} == {"site.test"}
    assert s0.navigation is not None
    assert s0.navigation.status == 200
    assert s0.navigation.page_title == "Clean fixture"


async def test_tracking_site_cookies_are_recorded_with_timing_and_attributes(
    sites: FixtureSites, settings: ScannerSettings, guard: SsrfGuard
) -> None:
    _, s0, _ = await _baseline(sites.url("tracking.html"), settings, guard)
    cookies = {c.name: c for c in s0.cookies}

    assert {"sid", "_ga", "_ephemeral", "_late_tag"} <= cookies.keys()
    # Server-set session cookie keeps its attributes.
    assert cookies["sid"].http_only is True
    assert cookies["sid"].lifetime_seconds is None
    # Script-set analytics cookie asked for 2 years; the browser caps storage at
    # 400 days (RFC 6265bis). Evidence records what was actually stored.
    ga_lifetime = cookies["_ga"].lifetime_seconds
    assert ga_lifetime is not None
    assert CHROMIUM_MAX_COOKIE_LIFETIME_S - 120 < ga_lifetime <= CHROMIUM_MAX_COOKIE_LIFETIME_S
    # Deferred tag is observed later than the inline one.
    assert cookies["_late_tag"].first_observed_ms > cookies["_ga"].first_observed_ms
    # Set-then-deleted cookies are still evidence that storing happened.
    assert cookies["_ephemeral"].name == "_ephemeral"


async def test_cookie_values_are_never_persisted_in_clear(
    sites: FixtureSites, settings: ScannerSettings, guard: SsrfGuard
) -> None:
    _, s0, directory = await _baseline(sites.url("tracking.html"), settings, guard)

    raw_bundle = (directory / BUNDLE_FILENAME).read_text()
    assert "GA1.1.123456789" not in raw_bundle
    assert "visitor-identifier-0001" not in raw_bundle
    ga = next(c for c in s0.cookies if c.name == "_ga")
    assert ga.value.length == len("GA1.1.123456789.1700000000")


async def test_third_party_requests_are_recorded_before_any_interaction(
    sites: FixtureSites, settings: ScannerSettings, guard: SsrfGuard
) -> None:
    _, s0, _ = await _baseline(sites.url("tracking.html"), settings, guard)
    tracker = [r for r in s0.requests if urlsplit(r.url).hostname == "tracker.test"]

    pixel = next(r for r in tracker if "ev=pageview" in r.url)
    assert pixel.resource_type == "image"
    assert pixel.status == 200
    assert pixel.server_ip == "127.0.0.1"
    assert pixel.frame_url is not None
    assert "site.test" in pixel.frame_url
    late = next(r for r in tracker if "ev=late" in r.url)
    assert late.started_ms > pixel.started_ms
    # Requests are recorded in issue order.
    sequences = [r.sequence for r in s0.requests]
    assert sequences == sorted(sequences)


async def test_digest_groups_contacts_by_site_relative_to_the_page(
    sites: FixtureSites, settings: ScannerSettings, guard: SsrfGuard
) -> None:
    _, s0, _ = await _baseline(sites.url("tracking.html"), settings, guard)
    d = digest(s0)

    assert d.page_site == "site.test"
    first, *others = d.contacts
    assert (first.site, first.first_party) == ("site.test", True)
    assert {c.site for c in others} >= {"tracker.test"}
    assert d.third_party_sites == len(others)
    party = {cookie.name: first_party for cookie, first_party in d.cookies}
    assert party["sid"] is True


async def test_web_storage_is_captured_per_origin_including_third_party_frames(
    sites: FixtureSites, settings: ScannerSettings, guard: SsrfGuard
) -> None:
    _, s0, _ = await _baseline(sites.url("tracking.html"), settings, guard)
    entries = {(urlsplit(s.origin).hostname, s.area, s.key) for s in s0.storage}

    assert ("site.test", StorageArea.LOCAL, "_pk_id") in entries
    assert ("site.test", StorageArea.SESSION, "ab_bucket") in entries
    assert ("widget.test", StorageArea.LOCAL, "widget_visitor") in entries


async def test_dom_snapshot_includes_open_shadow_roots_and_screenshot_is_stored(
    sites: FixtureSites, settings: ScannerSettings, guard: SsrfGuard
) -> None:
    _, s0, directory = await _baseline(sites.url("shadow.html"), settings, guard)

    main = next(f for f in s0.frames if f.is_main)
    assert main.dom is not None
    html = (directory / main.dom.path).read_text()
    assert "Continuer sans accepter" in html
    assert s0.screenshot is not None
    png = (directory / s0.screenshot.path).read_bytes()
    assert png.startswith(b"\x89PNG")
    assert s0.screenshot.size_bytes == len(png)


async def test_redirect_chain_is_recorded(
    sites: FixtureSites, settings: ScannerSettings, guard: SsrfGuard
) -> None:
    _, s0, _ = await _baseline(sites.url("redirect-chain"), settings, guard)

    assert s0.navigation is not None
    assert s0.navigation.redirect_chain == (sites.url("redirect-chain"),)
    assert s0.navigation.final_url == sites.url("clean.html")


async def test_redirect_to_metadata_endpoint_is_blocked(
    sites: FixtureSites, settings: ScannerSettings, guard: SsrfGuard
) -> None:
    _, s0, _ = await _baseline(sites.url("redirect-to-metadata"), settings, guard)

    assert s0.outcome is SessionOutcome.BLOCKED
    assert s0.error is not None
    assert "169.254.169.254" in s0.error
    blocked = [r for r in s0.requests if r.blocked_by is not None]
    assert [urlsplit(r.url).hostname for r in blocked] == ["169.254.169.254"]
    assert blocked[0].blocked_by is BlockReason.NON_PUBLIC_ADDRESS


async def test_private_subresources_and_websockets_are_blocked_but_recorded(
    sites: FixtureSites, settings: ScannerSettings, guard: SsrfGuard
) -> None:
    _, s0, _ = await _baseline(sites.url("private-subresources.html"), settings, guard)

    blocked_hosts = {urlsplit(r.url).hostname for r in s0.requests if r.blocked_by}
    assert blocked_hosts == {"10.0.0.1", "169.254.169.254", "192.168.1.1"}
    ws = next(r for r in s0.requests if r.resource_type == "websocket")
    assert ws.blocked_by is BlockReason.NON_PUBLIC_ADDRESS
    # The public pixel on the same page still loads: the guard is surgical.
    assert any(r.status == 200 and "ok=1" in r.url for r in s0.requests)
    # Nothing reached a non-public address.
    assert s0.guard_violations == ()
    assert s0.outcome is SessionOutcome.COMPLETED


async def test_bot_challenge_is_reported_not_analysed(
    sites: FixtureSites, settings: ScannerSettings, guard: SsrfGuard
) -> None:
    _, s0, _ = await _baseline(sites.url("challenge"), settings, guard)

    assert s0.outcome is SessionOutcome.OBSTRUCTED
    assert s0.obstruction is not None
    assert s0.obstruction.kind is ObstructionKind.BOT_CHALLENGE
    assert s0.obstruction.provider == "Cloudflare"


async def test_http_error_page_is_obstruction(
    sites: FixtureSites, settings: ScannerSettings, guard: SsrfGuard
) -> None:
    _, s0, _ = await _baseline(sites.url("not-found"), settings, guard)

    assert s0.outcome is SessionOutcome.OBSTRUCTED
    assert s0.obstruction is not None
    assert s0.obstruction.kind is ObstructionKind.HTTP_ERROR


async def test_unreachable_host_fails_cleanly(
    settings: ScannerSettings, guard: SsrfGuard, sites: FixtureSites
) -> None:
    # Resolves (fixture resolver) but nothing listens on this port.
    _, s0, _ = await _baseline("http://site.test:9/", settings, guard)

    assert s0.outcome is SessionOutcome.FAILED
    assert s0.error is not None
    assert s0.error.startswith("Navigation failed")


async def test_bundle_on_disk_round_trips_and_records_environment(
    sites: FixtureSites, settings: ScannerSettings, guard: SsrfGuard
) -> None:
    bundle, _, directory = await _baseline(sites.url("clean.html"), settings, guard)

    data = json.loads((directory / BUNDLE_FILENAME).read_text())
    assert EvidenceBundle.model_validate(data) == bundle
    env = bundle.environment
    assert env.vantage_point == "test:loopback"
    assert env.locale == "fr-FR"
    assert "HeadlessChrome" not in env.user_agent
    assert env.engine_version.split(".")[0] in env.user_agent
