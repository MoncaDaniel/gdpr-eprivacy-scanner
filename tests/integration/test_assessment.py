"""End to end against hermetic fixture sites: real Chromium -> report.

One fixture site per violation pattern (design review §6, Phase 2). The
fixture world's hosts (tracker.test, cmp.test, widget.test) are classified by
a test-only knowledge-base overlay, never by the packaged data.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path

import pytest

from privacy_scanner.classifier.knowledge import KnowledgeBase, build_knowledge_base
from privacy_scanner.collector.service import collect
from privacy_scanner.config import ScannerSettings
from privacy_scanner.domain.classification import BannerConfidence
from privacy_scanner.domain.report import Regulation, Report, Verdict
from privacy_scanner.intake.ssrf_guard import SsrfGuard
from privacy_scanner.pipeline import assess
from privacy_scanner.reporting.render import write_report
from tests.fixtures.server import FixtureSites

pytestmark = pytest.mark.integration

OVERLAY = Path(__file__).parents[1] / "fixtures" / "kb"
P, F, R, NA = Verdict.PASS, Verdict.FAIL, Verdict.MANUAL_REVIEW, Verdict.NOT_APPLICABLE


@pytest.fixture(scope="module")
def kb() -> KnowledgeBase:
    return build_knowledge_base([OVERLAY])


Scan = Callable[[str], Awaitable[Report]]


@pytest.fixture
def scan(
    sites: FixtureSites, settings: ScannerSettings, guard: SsrfGuard, kb: KnowledgeBase
) -> Scan:
    async def run(page: str) -> Report:
        result = await collect(sites.url(page), settings, guard=guard)
        return assess(result.bundle, knowledge_base=kb)

    return run


@pytest.mark.parametrize(
    ("page", "expected"),
    [
        ("clean.html", {"EP-01": P, "EP-02": P, "EP-03": P, "EP-04": NA, "EP-05": NA, "EP-09": NA}),
        (
            "consent-first.html",
            {"EP-01": P, "EP-02": P, "EP-03": P, "EP-04": P, "EP-05": P, "EP-09": NA},
        ),
        ("tracking.html", {"EP-01": F, "EP-02": F, "EP-03": R, "EP-04": P, "EP-05": P, "EP-09": F}),
        ("no-reject.html", {"EP-01": F, "EP-04": P, "EP-05": F}),
        ("no-banner.html", {"EP-01": F, "EP-02": F, "EP-04": F, "EP-05": NA}),
        ("iframe-banner.html", {"EP-04": P, "EP-05": P}),
        ("shadow-banner.html", {"EP-01": F, "EP-04": P, "EP-05": P}),
        ("close-only.html", {"EP-01": F, "EP-04": P, "EP-05": R}),
        ("unknown-cookie.html", {"EP-01": R, "EP-03": R, "EP-04": NA}),
    ],
)
async def test_fixture_site_verdicts(page: str, expected: dict[str, Verdict], scan: Scan) -> None:
    report = await scan(page)
    actual = {rule: report.finding(rule).verdict for rule in expected}  # type: ignore[union-attr]
    assert actual == expected


async def test_hidden_second_layer_reject_does_not_count(scan: Scan) -> None:
    report = await scan("no-reject.html")
    banner = report.classification.banner
    assert banner is not None
    labels = [c.label for c in banner.controls]
    assert "Tout refuser" not in labels  # display:none in the DOM, never visible
    assert labels == ["Accepter & fermer", "Paramétrer"]


async def test_shadow_root_banner_identifies_the_cmp_from_its_host(scan: Scan) -> None:
    report = await scan("shadow-banner.html")
    banner = report.classification.banner
    assert banner is not None
    assert banner.cmp == "Usercentrics"
    assert banner.confidence is BannerConfidence.HIGH
    assert "usercentrics-root >> " in banner.element


async def test_cross_origin_iframe_banner(scan: Scan) -> None:
    report = await scan("iframe-banner.html")
    banner = report.classification.banner
    assert banner is not None
    assert not banner.in_main_frame
    assert banner.frame_url.startswith("http://cmp.test:")


async def test_consent_first_site_scores_full_marks_on_its_coverage(scan: Scan) -> None:
    report = await scan("consent-first.html")
    eprivacy = report.score_for(Regulation.EPRIVACY)
    assert eprivacy is not None
    assert eprivacy.score == 100
    assert eprivacy.coverage_label == "based on 5 of 11 catalogued checks"
    gdpr = report.score_for(Regulation.GDPR)
    assert gdpr is not None and gdpr.score is None


async def test_bot_challenge_is_never_judged(scan: Scan) -> None:
    report = await scan("challenge")
    assert all(s.score is None for s in report.scores)
    automated = [f for f in report.findings if f.rule_id not in ("EP-10", "EP-11")]
    assert {f.verdict for f in automated} == {Verdict.ERROR}


async def test_written_report_is_self_contained(
    sites: FixtureSites,
    settings: ScannerSettings,
    guard: SsrfGuard,
    kb: KnowledgeBase,
) -> None:
    result = await collect(sites.url("tracking.html"), settings, guard=guard)
    report = assess(result.bundle, knowledge_base=kb)
    written = write_report(report, result.directory)
    html = written.html_path.read_text("utf-8")
    assert 'src="data:image/png;base64,' in html  # the S0 screenshot, embedded
    assert written.json_path.is_file()
