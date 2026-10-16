"""Report renderings: canonical JSON and a self-contained HTML page (ADR-0016).

The HTML report makes **no network requests**: no web fonts, no CDN, no
analytics. CSS is inline and the screenshot is embedded as a data URI, so the
file can be archived, e-mailed or printed and still show exactly what it
showed when generated. A privacy report that leaked its reader's IP address to
a font host would undercut itself.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape

from privacy_scanner.domain.report import Regulation, Report, Verdict
from privacy_scanner.formatting import lifetime, seconds

REPORT_JSON = "report.json"
REPORT_HTML = "report.html"
MAX_EMBEDDED_SCREENSHOT_BYTES = 4_000_000

_VERDICT_ORDER = {
    Verdict.FAIL: 0,
    Verdict.MANUAL_REVIEW: 1,
    Verdict.ERROR: 2,
    Verdict.PASS: 3,
    Verdict.NOT_APPLICABLE: 4,
}


@dataclass(frozen=True, slots=True)
class WrittenReport:
    json_path: Path
    html_path: Path


@cache
def _environment() -> Environment:
    env = Environment(
        loader=PackageLoader("privacy_scanner.reporting", "templates"),
        autoescape=select_autoescape(["html", "j2"], default_for_string=True),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    filters: dict[str, Callable[..., Any]] = {
        "seconds": seconds,
        "lifetime": lifetime,
        "humanize": lambda value: str(value).replace("_", " "),
        "utc": lambda dt: dt.strftime("%d %b %Y, %H:%M UTC"),
        "short_hash": lambda value: str(value)[:12],
    }
    env.filters.update(filters)
    return env


def render_html(
    report: Report, screenshot_png: bytes | None = None, *, expand_all: bool = False
) -> str:
    """Render the report page. ``expand_all`` opens every finding (print/PDF)."""
    screenshot_uri = None
    if screenshot_png and len(screenshot_png) <= MAX_EMBEDDED_SCREENSHOT_BYTES:
        screenshot_uri = "data:image/png;base64," + base64.b64encode(screenshot_png).decode()
    findings = sorted(
        report.findings,
        key=lambda f: (
            f.regulation is not Regulation.EPRIVACY,
            _VERDICT_ORDER[f.verdict],
            f.rule_id,
        ),
    )
    counts = {v: sum(1 for f in report.findings if f.verdict is v) for v in Verdict}
    return (
        _environment()
        .get_template("report.html.j2")
        .render(
            report=report,
            findings=findings,
            counts=counts,
            Verdict=Verdict,
            screenshot_uri=screenshot_uri,
            expand_all=expand_all,
        )
    )


def write_report(report: Report, directory: Path) -> WrittenReport:
    """Write ``report.json`` and ``report.html`` next to the evidence bundle."""
    directory.mkdir(parents=True, exist_ok=True)
    json_path = directory / REPORT_JSON
    json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")

    screenshot: bytes | None = None
    if report.scan.screenshot_path:
        candidate = (directory / report.scan.screenshot_path).resolve()
        if directory.resolve() in candidate.parents and candidate.is_file():
            screenshot = candidate.read_bytes()
    html_path = directory / REPORT_HTML
    html_path.write_text(render_html(report, screenshot), encoding="utf-8")
    return WrittenReport(json_path=json_path, html_path=html_path)
