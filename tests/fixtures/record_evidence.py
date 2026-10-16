"""Record Evidence Bundles from the fixture sites for golden tests.

    uv run python -m tests.fixtures.record_evidence

Bundles are written to ``tests/fixtures/evidence/<page>.json`` (artefacts such
as DOM snapshots and screenshots are not kept; golden tests judge the bundle
alone). Re-record only when the collector's output format changes, then
regenerate the golden reports with ``UPDATE_GOLDEN=1 uv run pytest tests/golden``.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from privacy_scanner.collector.service import collect
from privacy_scanner.config import ScannerSettings
from privacy_scanner.intake.ssrf_guard import NetworkPolicy, SsrfGuard
from tests.fixtures.server import serve_fixture_sites

PAGES = (
    "clean.html",
    "consent-first.html",
    "tracking.html",
    "no-reject.html",
    "no-banner.html",
    "close-only.html",
    "unknown-cookie.html",
)
EVIDENCE_DIR = Path(__file__).parent / "evidence"


async def _resolver(host: str, port: int) -> list[str]:
    if host.endswith(".test"):
        return ["127.0.0.1"]
    raise OSError(host)


async def main() -> None:
    guard = SsrfGuard(
        policy=NetworkPolicy(allowed_ports=None, allow_loopback=True), resolver=_resolver
    )
    with serve_fixture_sites() as sites, tempfile.TemporaryDirectory() as scratch:
        settings = ScannerSettings(
            output_dir=Path(scratch),
            observation_window_s=1.5,
            network_idle_timeout_s=3.0,
            allowed_ports=None,
            allow_loopback=True,
            vantage_point="test:loopback",
        )
        for page in PAGES:
            name = page.removesuffix(".html")
            result = await collect(sites.url(page), settings, guard=guard, scan_id=f"golden-{name}")
            target = EVIDENCE_DIR / f"{name}.json"
            target.write_text(result.bundle.model_dump_json(indent=2) + "\n", encoding="utf-8")
            print(target)


if __name__ == "__main__":
    asyncio.run(main())
