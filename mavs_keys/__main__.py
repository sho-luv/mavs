"""Command-line reporting for managed constant inspection."""

from pathlib import Path
from typing import Annotated

import typer

from mavs_keys.scanner import scan


def main(
    file: Annotated[Path, typer.Option("--file", "-f", help="APK or XAPK to inspect")],
    *,
    json_output: Annotated[bool, typer.Option("--json", "-j")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Report embedded managed credentials without disclosing constant values."""
    report = scan(file)
    incomplete = any(item.status != "scanned" for item in report.coverage)
    if json_output:
        typer.echo(report.model_dump_json(indent=2))
    else:
        typer.echo(f"Managed key scan: {len(report.findings)} finding(s)")
        typer.echo(report.scope)
        for finding in report.findings:
            label = f"[{finding.severity.upper()}] {finding.rule_id}"
            field = f"{finding.type_name}::{finding.field_name}"
            typer.echo(f"{label} {field} ({finding.byte_length} bytes; value redacted)")
            typer.echo(f"  Source: {finding.source}")
            if verbose:
                typer.echo(f"  SHA-256 fingerprint: {finding.fingerprint}")
                typer.echo(f"  Read by: {', '.join(finding.used_by)}")
                typer.echo(f"  Evidence: {finding.evidence}")
        for item in report.coverage:
            if item.status != "scanned":
                typer.echo(f"NOT SCANNED [{item.status}]: {item.source}: {item.detail}")
        typer.echo(
            "Coverage incomplete."
            if incomplete
            else "Supported patterns inspected; absence of findings is not proof of security."
        )
    raise typer.Exit(code=2 if incomplete else 0)


if __name__ == "__main__":
    app = typer.Typer(pretty_exceptions_enable=False, pretty_exceptions_show_locals=False)
    _ = app.command()(main)
    app()
