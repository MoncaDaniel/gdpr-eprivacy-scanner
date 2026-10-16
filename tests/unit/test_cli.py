"""CLI contract: exit codes scripts can rely on (no browser is launched here)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from privacy_scanner.cli import EXIT_NOT_OBSERVED, EXIT_REJECTED, app

runner = CliRunner()


@pytest.mark.parametrize(
    ("url", "message"),
    [
        ("ftp://example.com/", "Invalid URL"),
        ("https://user:pw@example.com/", "Invalid URL"),
        ("http://localhost/", "Refused"),
        ("http://169.254.169.254/latest/meta-data/", "Refused"),
        ("http://0xa9fea9fe/", "Refused"),
    ],
)
def test_rejected_input_exits_2_before_any_browser_work(
    url: str, message: str, tmp_path: Path
) -> None:
    result = runner.invoke(app, ["collect", url, "--out", str(tmp_path)])
    assert result.exit_code == EXIT_REJECTED
    assert message in result.output
    assert list(tmp_path.iterdir()) == []  # nothing was collected or written


def test_version_prints_something() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.output.strip()


@pytest.mark.parametrize("command", ["scan", "collect"])
def test_scan_rejects_like_collect(command: str, tmp_path: Path) -> None:
    result = runner.invoke(app, [command, "http://localhost/", "--out", str(tmp_path)])
    assert result.exit_code == EXIT_REJECTED
    assert list(tmp_path.iterdir()) == []


EVIDENCE = Path(__file__).parents[1] / "fixtures" / "evidence"


def test_assess_rejudges_a_stored_bundle_without_network(tmp_path: Path) -> None:
    bundle = tmp_path / "evidence.json"
    bundle.write_bytes((EVIDENCE / "no-reject.json").read_bytes())
    result = runner.invoke(app, ["assess", str(bundle)])
    assert result.exit_code == 0, result.output
    assert "EP-05" in result.output
    assert "Issue detected" in result.output
    assert "based on 5 of 11 catalogued checks" in result.output
    assert (tmp_path / "report.html").is_file()
    assert (tmp_path / "report.json").is_file()


def test_assess_unobserved_bundle_exits_3_but_writes_report(tmp_path: Path) -> None:
    raw = json.loads((EVIDENCE / "clean.json").read_text("utf-8"))
    raw["sessions"][0]["outcome"] = "obstructed"
    raw["sessions"][0]["error"] = "Cloudflare challenge"
    bundle = tmp_path / "evidence.json"
    bundle.write_text(json.dumps(raw))
    result = runner.invoke(app, ["assess", str(bundle)])
    assert result.exit_code == EXIT_NOT_OBSERVED
    assert "not scored" in result.output
    assert (tmp_path / "report.html").is_file()


@pytest.mark.parametrize("content", [None, "{not json", '{"schema_version": "1.1.0"}'])
def test_assess_unreadable_bundle_exits_2(content: str | None, tmp_path: Path) -> None:
    bundle = tmp_path / "evidence.json"
    if content is not None:
        bundle.write_text(content)
    result = runner.invoke(app, ["assess", str(bundle)])
    assert result.exit_code == EXIT_REJECTED
    assert "Cannot read evidence bundle" in result.output
