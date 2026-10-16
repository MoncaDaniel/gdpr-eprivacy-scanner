"""Scoring formula, coverage, and the HTML/JSON renderings."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from privacy_scanner.domain.evidence import SessionOutcome
from privacy_scanner.domain.report import Regulation, Report, Verdict
from privacy_scanner.pipeline import assess
from privacy_scanner.reporting.render import render_html, write_report
from tests import builders as b

# 1x1 transparent PNG.
PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010806000000"
    "1f15c4890000000d4944415478da63f8ffff3f0005fe02fea7d6a4cf0000000049454e44ae426082"
)


def _report(**kwargs: object) -> Report:
    return assess(b.bundle(**kwargs))


# --------------------------------------------------------------------------- scoring
def test_score_is_severity_weighted_over_pass_and_fail_only() -> None:
    # EP-01 FAIL (high 5), EP-04 FAIL (high 5) -> trackers, no banner.
    # EP-02 PASS (5), EP-03 PASS (3), EP-09 PASS (low 1) [_ga 30 days].
    # EP-05 N/A. EP-10/11 review. Score = 9 / 19.
    report = _report(cookies=(b.cookie("_ga"),))
    s = report.score_for(Regulation.EPRIVACY)
    assert s is not None
    verdicts = {f.rule_id: f.verdict for f in report.findings}
    assert verdicts["EP-01"] is Verdict.FAIL
    assert verdicts["EP-04"] is Verdict.FAIL
    assert verdicts["EP-05"] is Verdict.NOT_APPLICABLE
    assert s.score == round(100 * 9 / 19)
    assert (s.passed, s.failed, s.scored) == (3, 2, 5)
    assert s.manual_review == 2
    assert s.not_applicable == 1
    assert s.not_yet_evaluated == 3
    assert s.catalogued == 11
    assert s.coverage_label == "based on 5 of 11 catalogued checks"


def test_regulation_without_scored_checks_has_no_score() -> None:
    s = _report().score_for(Regulation.GDPR)
    assert s is not None
    assert s.score is None
    assert s.scored == 0
    assert s.not_yet_evaluated == 13


def test_unobserved_page_has_no_score() -> None:
    report = assess(b.bundle(b.session(outcome=SessionOutcome.OBSTRUCTED)))
    assert all(s.score is None for s in report.scores)


# --------------------------------------------------------------------------- reporting
BANNED = re.compile(r"\b(non-?)?compliant\b|\bcompliance score\b|%\s*compliant", re.IGNORECASE)


@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"cookies": (b.cookie("_ga", lifetime_s=400 * b.DAY), b.cookie("zz"))},
        {"consent_ui": b.banner("J'accepte", "×"), "cookies": (b.cookie("_fbp"),)},
    ],
)
def test_no_banned_vocabulary_in_any_rendering(kwargs: dict[str, object]) -> None:
    report = _report(**kwargs)
    assert not BANNED.search(render_html(report))
    assert not BANNED.search(report.model_dump_json())


def test_catalog_and_templates_contain_no_banned_vocabulary() -> None:
    root = Path(__file__).parents[2] / "src" / "privacy_scanner"
    for path in [*root.glob("rules/catalog/*.yaml"), *root.glob("reporting/templates/*")]:
        assert not BANNED.search(path.read_text("utf-8")), path


def test_html_loads_no_external_resources() -> None:
    html = render_html(_report(cookies=(b.cookie("_ga"),)), PNG)
    # Only <a href> may point outside; nothing that the browser fetches by itself.
    fetched = re.findall(
        r"<(?:img|script|link|iframe|source|video|audio|object|embed)\b[^>]*?\b(?:src|href|data)=\"([^\"]*)\"",
        html,
    )
    assert fetched, "expected the embedded screenshot"
    assert all(value.startswith("data:") for value in fetched), fetched
    assert "<script" not in html
    assert 'src="data:image/png;base64,' in html
    assert "default-src 'none'" in html
    assert "@import" not in html and "url(" not in html


def test_html_escapes_page_supplied_text() -> None:
    hostile = '<img src=x onerror="alert(1)">'
    bundle = b.bundle(
        consent_ui=b.banner("Tout accepter", hostile, text="Cookies " + hostile),
        cookies=(b.cookie(hostile),),
    )
    html = render_html(assess(bundle))
    assert hostile not in html
    assert "&lt;img src=x onerror=" in html


def test_findings_are_ordered_issues_first_and_open() -> None:
    html = render_html(_report(cookies=(b.cookie("_ga"),)))
    order = re.findall(r'<details class="finding" id="(EP-\d\d)"( open)?', html)
    ids = [rid for rid, _ in order]
    assert ids[:2] == ["EP-01", "EP-04"]  # the two issues
    assert dict(order)["EP-01"] == " open"
    assert dict(order)["EP-02"] == ""
    expanded = render_html(_report(cookies=(b.cookie("_ga"),)), expand_all=True)
    assert all(
        flag == " open"
        for _, flag in re.findall(r'<details class="finding" id="(EP-\d\d)"( open)?', expanded)
    )


def test_unavailable_page_is_announced() -> None:
    html = render_html(assess(b.bundle(b.session(outcome=SessionOutcome.OBSTRUCTED))))
    assert "Results unavailable" in html
    assert "Not scored" in html


def test_write_report_round_trips_json_and_embeds_contained_screenshot(tmp_path: Path) -> None:
    report = _report(cookies=(b.cookie("_ga"),))
    written = write_report(report, tmp_path)
    assert Report.model_validate_json(written.json_path.read_text("utf-8")) == report
    assert "data:image/png" not in written.html_path.read_text("utf-8")  # no screenshot ref

    # A screenshot path escaping the scan directory is never read.
    (tmp_path.parent / "secret.png").write_bytes(PNG)
    escaped = report.model_copy(
        update={"scan": report.scan.model_copy(update={"screenshot_path": "../secret.png"})}
    )
    html = write_report(escaped, tmp_path).html_path.read_text("utf-8")
    assert "data:image/png" not in html

    (tmp_path / "s0_baseline").mkdir()
    (tmp_path / "s0_baseline" / "screenshot.png").write_bytes(PNG)
    inside = report.model_copy(
        update={
            "scan": report.scan.model_copy(update={"screenshot_path": "s0_baseline/screenshot.png"})
        }
    )
    assert "data:image/png" in write_report(inside, tmp_path).html_path.read_text("utf-8")


def test_report_records_reproducibility_metadata() -> None:
    report = _report()
    assert report.catalog.version == "1.0.0"
    assert len(report.catalog.sha256) == 64
    assert report.knowledge_base.open_cookie_database_commit
    assert report.scan.evidence_schema_version == "1.1.0"
    assert report.limitations
    assert "not legal advice" in report.disclaimer
