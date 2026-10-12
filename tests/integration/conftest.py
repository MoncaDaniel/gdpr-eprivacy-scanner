"""Integration fixtures: hermetic fixture sites + a guard/settings pair for them."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from privacy_scanner.config import ScannerSettings
from privacy_scanner.intake.ssrf_guard import NetworkPolicy, SsrfGuard
from tests.fixtures.server import FixtureSites, serve_fixture_sites

pytestmark = pytest.mark.integration


async def _test_resolver(host: str, port: int) -> list[str]:
    """``*.test`` is the fixture server on loopback; nothing else resolves.

    The session's egress proxy is the browser's only resolver (ADR-0011), so
    this is the whole DNS of the test world.
    """
    if host.endswith(".test"):
        return ["127.0.0.1"]
    raise OSError(f"fixture resolver: unknown host {host}")


@pytest.fixture(scope="session")
def sites() -> Iterator[FixtureSites]:
    with serve_fixture_sites() as fixture_sites:
        yield fixture_sites


@pytest.fixture
def settings(tmp_path: Path) -> ScannerSettings:
    return ScannerSettings(
        output_dir=tmp_path,
        observation_window_s=1.5,
        network_idle_timeout_s=3.0,
        navigation_timeout_s=15.0,
        cookie_poll_interval_s=0.1,
        allowed_ports=None,
        allow_loopback=True,
        vantage_point="test:loopback",
    )


@pytest.fixture
def guard() -> SsrfGuard:
    return SsrfGuard(
        policy=NetworkPolicy(allowed_ports=None, allow_loopback=True), resolver=_test_resolver
    )
