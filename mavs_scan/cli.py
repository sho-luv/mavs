"""Typer command-line interface for the static scanner and web dashboard."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from mavs_scan.engine import scan as run_scan
from mavs_scan.model import ScanReport
from mavs_scan.report import render

app = typer.Typer(
    add_completion=False,
    pretty_exceptions_enable=False,
    pretty_exceptions_show_locals=False,
    help="MAVS static analysis for Android APK/XAPK packages.",
)


def _incomplete(report: ScanReport) -> bool:
    return any(item.status != "ok" for item in report.coverage)


@app.command()
def scan(  # noqa: PLR0913
    file: Annotated[Path, typer.Option("--file", "-f", exists=True, help="APK or XAPK to scan")],
    *,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show evidence and verify steps")
    ] = False,
    exploit: Annotated[
        bool, typer.Option("--exploit", "-e", help="Show exploitation guidance")
    ] = False,
    json_output: Annotated[bool, typer.Option("--json", "-j", help="Emit the JSON report")] = False,
    skip_managed_keys: Annotated[
        bool, typer.Option("--skip-managed-keys", help="Skip the slow Xamarin/.NET key scan")
    ] = False,
    web: Annotated[
        bool, typer.Option("--web", help="Serve the result in a browser after scanning")
    ] = False,
    host: Annotated[str, typer.Option("--host", help="Web bind host")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", help="Web bind port")] = 8000,
) -> None:
    """Run a full static scan of one package."""
    report = run_scan(file, managed_keys=not skip_managed_keys)
    if json_output:
        typer.echo(report.model_dump_json(indent=2))
    else:
        render(report, verbose=verbose, exploit=exploit)
    if web:
        from mavs_scan.web.server import serve  # noqa: PLC0415

        serve(report, host=host, port=port)
        return
    raise typer.Exit(code=2 if _incomplete(report) else 0)


@app.command()
def serve(
    file: Annotated[
        Path | None, typer.Option("--file", "-f", exists=True, help="Seed with a scan")
    ] = None,
    *,
    skip_managed_keys: Annotated[
        bool, typer.Option("--skip-managed-keys", help="Skip the slow Xamarin/.NET key scan")
    ] = False,
    host: Annotated[str, typer.Option("--host", help="Bind host")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", help="Bind port")] = 8000,
) -> None:
    """Start the web dashboard, optionally seeded with a scan of ``file``."""
    from mavs_scan.web.server import serve as serve_web  # noqa: PLC0415

    report = run_scan(file, managed_keys=not skip_managed_keys) if file is not None else None
    serve_web(report, host=host, port=port)


if __name__ == "__main__":
    app()
