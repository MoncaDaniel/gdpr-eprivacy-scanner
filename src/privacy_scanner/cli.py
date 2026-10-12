"""Command-line interface: ``privacy-scanner collect <url>``.

Exit codes: 0 evidence collected; 2 input rejected (invalid URL or forbidden
destination); 3 collection ran but the page could not be observed (blocked,
obstructed or failed). Scripts can rely on these.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from privacy_scanner.collector.service import TargetRejectedError, collect, scanner_version
from privacy_scanner.collector.summary import digest
from privacy_scanner.config import ScannerSettings
from privacy_scanner.domain.evidence import EvidenceBundle, SessionEvidence, SessionOutcome
from privacy_scanner.intake.url import InvalidUrlError

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
    before any consent interaction (session S0)."""
    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    overrides: dict[str, object] = {}
    if output_dir is not None:
        overrides["output_dir"] = output_dir
    if observe is not None:
        overrides["observation_window_s"] = observe
    settings = ScannerSettings(**overrides)  # type: ignore[arg-type]

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
