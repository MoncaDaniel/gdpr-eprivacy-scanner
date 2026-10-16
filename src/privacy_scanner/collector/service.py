"""Collection use case: URL in, persisted Evidence Bundle out.

This is the collector's only public entry point. It owns the lifecycle of the
Playwright driver and browser, so callers (CLI now, API worker in Phase 4)
never deal with browser resources.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from playwright.async_api import async_playwright

from privacy_scanner.collector.artifacts import LocalArtifactStore
from privacy_scanner.collector.browser import browser_environment, launch_browser
from privacy_scanner.collector.fingerprint import ValueFingerprinter
from privacy_scanner.collector.sessions import SessionDeps, run_baseline_session
from privacy_scanner.config import ScannerSettings
from privacy_scanner.domain.evidence import EvidenceBundle, ScanTarget
from privacy_scanner.intake.ssrf_guard import GuardDecision, SsrfGuard
from privacy_scanner.intake.url import normalize_url
from privacy_scanner.version import scanner_version

__all__ = [
    "BUNDLE_FILENAME",
    "CollectionResult",
    "TargetRejectedError",
    "collect",
    "scanner_version",
]

logger = logging.getLogger(__name__)

BUNDLE_FILENAME = "evidence.json"


class TargetRejectedError(Exception):
    """The target URL failed the pre-flight network policy check."""

    def __init__(self, url: str, decision: GuardDecision) -> None:
        super().__init__(f"{url} cannot be scanned: {decision.detail}")
        self.url = url
        self.decision = decision


@dataclass(frozen=True, slots=True)
class CollectionResult:
    bundle: EvidenceBundle
    directory: Path
    """Directory holding ``evidence.json`` and all artefacts it references."""

    @property
    def bundle_path(self) -> Path:
        return self.directory / BUNDLE_FILENAME


async def collect(
    raw_url: str,
    settings: ScannerSettings,
    *,
    guard: SsrfGuard | None = None,
    scan_id: str | None = None,
) -> CollectionResult:
    """Collect evidence for ``raw_url``.

    Raises:
        InvalidUrlError: the input is not a scannable http(s) URL.
        TargetRejectedError: the target resolves to a forbidden destination.
    """
    target = normalize_url(raw_url)
    guard = guard or SsrfGuard(policy=settings.network_policy())
    decision = await guard.check_host(target.host, target.port)
    if not decision.allowed:
        raise TargetRejectedError(target.url, decision)

    scan_id = scan_id or uuid.uuid4().hex
    directory = settings.output_dir / scan_id
    store = LocalArtifactStore(directory)
    created_at = datetime.now(UTC)
    logger.info("scan %s: collecting %s", scan_id, target.url)

    async with async_playwright() as playwright:
        browser = await launch_browser(playwright, settings)
        try:
            environment = browser_environment(browser, settings)
            deps = SessionDeps(
                browser=browser,
                environment=environment,
                settings=settings,
                guard=guard,
                store=store,
                fingerprinter=ValueFingerprinter(),
            )
            baseline = await run_baseline_session(target.url, deps)
        finally:
            await browser.close()

    bundle = EvidenceBundle(
        scan_id=scan_id,
        scanner_version=scanner_version(),
        created_at=created_at,
        target=ScanTarget(input_url=raw_url, normalized_url=target.url),
        environment=environment,
        sessions=(baseline,),
    )
    store.put(BUNDLE_FILENAME, bundle.model_dump_json(indent=2).encode(), "application/json")
    logger.info("scan %s: %s in %d ms", scan_id, baseline.outcome, baseline.duration_ms)
    return CollectionResult(bundle=bundle, directory=directory)
