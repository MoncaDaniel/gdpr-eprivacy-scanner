"""Command-line interface.

* ``privacy-scanner scan <url>``: collect evidence, judge it, write
  ``report.json`` + ``report.html`` next to the evidence bundle.
* ``privacy-scanner assess <evidence.json>``: re-judge a stored bundle against
  the current rule catalog, without visiting the site again.
* ``privacy-scanner collect <url>``: evidence only (Phase 1 behaviour).

Exit codes: 0 success; 2 input rejected (invalid URL or forbidden
destination, unreadable bundle); 3 the page could not be observed (blocked,
obstructed or failed; a report is still written, marked as unavailable).
Scripts can rely on these.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from privacy_scanner.collector.service import (
    TargetRejectedError,
    collect,
    scanner_version,
)
from privacy_scanner.collector.summary import digest
from privacy_scanner.config import ScannerSettings
from privacy_scanner.domain.evidence import EvidenceBundle, SessionEvidence, SessionOutcome
from privacy_scanner.domain.report import Report, Verdict
from privacy_scanner.intake.url import InvalidUrlError
from privacy_scanner.pipeline import assess
from privacy_scanner.reporting.render import WrittenReport, write_report

EXIT_REJECTED = 2
EXIT_NOT_OBSERVED = 3

app = typer.Typer(
    name="privacy-scanner",
    help="Evidence-based GDPR + ePrivacy website scanner.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)

DISCLAIMER = (
    "Technical observation of one page load from one vantage point. "
    "Not a legal assessment and not legal advice."
)


def _settings(output_dir: Path | None, observe: float | None) -> ScannerSettings:
    overrides: dict[str, object] = {}
    if output_dir is not None:
        overrides["output_dir"] = output_dir
    if observe is not None:
        overrides["observation_window_s"] = observe
    return ScannerSettings(**overrides)  # type: ignore[arg-type]


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


@app.command("scan")
def scan_command(
    url: Annotated[str, typer.Argument(help="Page to scan, e.g. https://www.example.fr")],
    output_dir: Annotated[
        Path | None, typer.Option("--out", "-o", help="Directory for scan folders.")
    ] = None,
    observe: Annotated[
        float | None,
        typer.Option("--observe", help="Seconds to observe after load (default 6)."),
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Observe a page before consent, judge it against the rule catalog and write
    an HTML + JSON report."""
    _configure_logging(verbose)
    settings = _settings(output_dir, observe)
    try:
        with console.status(f"Observing {url} …", spinner="dots"):
            result = asyncio.run(collect(url, settings))
    except InvalidUrlError as exc:
        err_console.print(f"[red]Invalid URL:[/] {exc}")
        raise typer.Exit(EXIT_REJECTED) from exc
    except TargetRejectedError as exc:
        err_console.print(f"[red]Refused:[/] {exc}")
        raise typer.Exit(EXIT_REJECTED) from exc

    report = assess(result.bundle)
    written = write_report(report, result.directory)
    _render_report(report, written)
    if report.scan.outcome is not SessionOutcome.COMPLETED:
        raise typer.Exit(EXIT_NOT_OBSERVED)


@app.command("assess")
def assess_command(
    bundle_path: Annotated[
        Path, typer.Argument(help="Path to an evidence.json written by scan/collect.")
    ],
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Re-judge a stored Evidence Bundle with the current rule catalog. The site is
    not contacted. Reports are written next to the bundle."""
    _configure_logging(verbose)
    try:
        bundle = EvidenceBundle.model_validate_json(bundle_path.read_bytes())
    except (OSError, ValidationError) as exc:
        err_console.print(f"[red]Cannot read evidence bundle:[/] {exc}")
        raise typer.Exit(EXIT_REJECTED) from exc
    report = assess(bundle)
    written = write_report(report, bundle_path.parent)
    _render_report(report, written)
    if report.scan.outcome is not SessionOutcome.COMPLETED:
        raise typer.Exit(EXIT_NOT_OBSERVED)


@app.command("collect")
def collect_command(
    url: Annotated[str, typer.Argument(help="Page to observe, e.g. https://www.example.fr")],
    output_dir: Annotated[
        Path | None, typer.Option("--out", "-o", help="Directory for scan folders.")
    ] = None,
    observe: Annotated[
        float | None,
        typer.Option("--observe", help="Seconds to observe after load (default 6)."),
    ] = None,
    as_json: Annotated[
        bool, typer.Option("--json", help="Print the Evidence Bundle JSON instead of a summary.")
    ] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Observe what a page stores on the device and which servers it contacts
    before any consent interaction (session S0). Evidence only, no judgement."""
    _configure_logging(verbose)
    settings = _settings(output_dir, observe)

    try:
        if as_json:
            result = asyncio.run(collect(url, settings))
        else:
            with console.status(f"Observing {url} …", spinner="dots"):
                result = asyncio.run(collect(url, settings))
    except InvalidUrlError as exc:
        err_console.print(f"[red]Invalid URL:[/] {exc}")
        raise typer.Exit(EXIT_REJECTED) from exc
    except TargetRejectedError as exc:
        err_console.print(f"[red]Refused:[/] {exc}")
        raise typer.Exit(EXIT_REJECTED) from exc

    session = result.bundle.sessions[0]
    if as_json:
        typer.echo(result.bundle.model_dump_json(indent=2))
    else:
        _render(result.bundle, session, result.bundle_path)
    if session.outcome is not SessionOutcome.COMPLETED:
        raise typer.Exit(EXIT_NOT_OBSERVED)


@app.command("version")
def version_command() -> None:
    """Print the scanner version."""
    typer.echo(scanner_version())


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
_OUTCOME_STYLE = {
    SessionOutcome.COMPLETED: "green",
    SessionOutcome.OBSTRUCTED: "yellow",
    SessionOutcome.BLOCKED: "red",
    SessionOutcome.FAILED: "red",
}


_VERDICT_STYLE = {
    Verdict.FAIL: "red",
    Verdict.MANUAL_REVIEW: "yellow",
    Verdict.PASS: "green",
    Verdict.NOT_APPLICABLE: "dim",
    Verdict.ERROR: "magenta",
}


def _render_report(report: Report, written: WrittenReport) -> None:
    lines = [
        f"[bold]Target[/]      {report.scan.final_url or report.scan.normalized_url}",
        f"[bold]Outcome[/]     {report.scan.outcome.value}"
        + (f" — {report.scan.outcome_detail}" if report.scan.outcome_detail else ""),
    ]
    for s in report.scores:
        value = f"{s.score} / 100" if s.score is not None else "not scored"
        lines.append(f"[bold]{s.title:<12}[/]{value}, {s.coverage_label}")
    console.print(Panel("\n".join(lines), title="Website Privacy Exposure Score", expand=False))

    table = Table(title="Findings", title_justify="left")
    for col in ("Rule", "Check", "Verdict", "Severity", "Confidence"):
        table.add_column(col)
    for f in report.findings:
        style = _VERDICT_STYLE[f.verdict]
        verdict = f"[{style}]{f.verdict_label}[/]"
        if f.review_reason:
            verdict += f" [dim]({f.review_reason.label.lower()})[/]"
        table.add_row(f.rule_id, f.title, verdict, f.severity.value, f.confidence.value)
    console.print(table)
    if report.not_yet_evaluated:
        planned = ", ".join(p.rule_id for p in report.not_yet_evaluated)
        console.print(f"[dim]Not yet evaluated in this version: {planned}[/]")
    console.print(f"Report: [bold]{written.html_path}[/]")
    console.print(f"[dim]JSON: {written.json_path}[/]")
    console.print(f"[dim]{report.disclaimer}[/]")


def _render(bundle: EvidenceBundle, session: SessionEvidence, bundle_path: Path) -> None:
    nav = session.navigation
    style = _OUTCOME_STYLE[session.outcome]
    lines = [
        f"[bold]Target[/]      {bundle.target.normalized_url}",
        f"[bold]Final URL[/]   {nav.final_url if nav else '—'}"
        + (f"  (HTTP {nav.status})" if nav and nav.status else ""),
        f"[bold]Outcome[/]     [{style}]{session.outcome.value}[/]"
        + (f" — {session.error}" if session.error else ""),
        f"[bold]Observed[/]    {session.observation_window_ms / 1000:.1f}s after load, "
        "no interaction",
        f"[bold]Vantage[/]     {bundle.environment.vantage_point} · "
        f"{bundle.environment.locale} · Chromium {bundle.environment.engine_version}",
    ]
    console.print(Panel("\n".join(lines), title="Session S0 — before any consent", expand=False))

    d = digest(session)
    if session.cookies:
        table = Table(title=f"Cookies stored ({len(session.cookies)})", title_justify="left")
        for col in ("Name", "Domain", "Party", "Lifetime", "First seen"):
            table.add_column(col)
        for cookie, first_party in d.cookies:
            table.add_row(
                cookie.name,
                cookie.domain,
                "first" if first_party else "[yellow]third[/]",
                _lifetime(cookie.lifetime_seconds),
                f"{cookie.first_observed_ms / 1000:.1f}s",
            )
        console.print(table)
    else:
        console.print("[green]No cookies were stored.[/]")

    if session.storage:
        table = Table(title=f"Web Storage keys ({len(session.storage)})", title_justify="left")
        for col in ("Origin", "Area", "Key", "Value length"):
            table.add_column(col)
        for item in session.storage:
            table.add_row(item.origin, item.area.value, item.key, str(item.value.length))
        console.print(table)

    table = Table(
        title=f"Sites contacted ({len(d.contacts)}, of which {d.third_party_sites} third-party)",
        title_justify="left",
    )
    for col in ("Site", "Party", "Requests", "Types", "First at", "Hosts"):
        table.add_column(col)
    for contact in d.contacts:
        types = ", ".join(f"{t} x{n}" for t, n in contact.resource_types[:4])
        blocked = f" ([red]{contact.blocked} blocked[/])" if contact.blocked else ""
        table.add_row(
            contact.site,
            "first" if contact.first_party else "[yellow]third[/]",
            f"{contact.requests}{blocked}",
            types,
            f"{contact.first_request_ms / 1000:.1f}s",
            ", ".join(contact.hosts[:3]) + (" …" if len(contact.hosts) > 3 else ""),
        )
    console.print(table)
    console.print(f"[dim]Evidence bundle: {bundle_path}[/]")
    console.print(f"[dim]{DISCLAIMER}[/]")


def _lifetime(seconds: int | None) -> str:
    if seconds is None:
        return "session"
    if seconds <= 0:
        return "expired"
    delta = timedelta(seconds=seconds)
    if delta.days >= 365:
        return f"{delta.days / 365.25:.1f} years"
    if delta.days >= 1:
        return f"{delta.days} days"
    return f"{seconds // 3600}h {seconds % 3600 // 60}m"


if __name__ == "__main__":  # pragma: no cover
    app()
