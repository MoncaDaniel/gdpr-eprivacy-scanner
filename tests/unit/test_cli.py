"""CLI contract: exit codes scripts can rely on (no browser is launched here)."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from privacy_scanner.cli import EXIT_REJECTED, app

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
