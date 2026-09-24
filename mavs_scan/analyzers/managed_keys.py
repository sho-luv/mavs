"""Adapter exposing the existing mavs_keys managed-constant scanner as an analyzer.

This preserves the MAVS-KEY-001 Xamarin/.NET embedded credential detection and
folds its findings and coverage into the unified report.
"""

from __future__ import annotations

from pathlib import Path

from mavs_keys.scanner import scan as scan_managed_keys
from mavs_scan.context import ScanContext
from mavs_scan.model import Finding, Severity

_SEVERITY = {"high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}


def analyze(ctx: ScanContext) -> list[Finding]:
    """Return managed-key findings for the original input path."""
    try:
        report = scan_managed_keys(Path(ctx.apk.path))
    except (OSError, ValueError) as exc:
        ctx.note("managed-keys", "error", f"managed key scan failed: {exc}")
        return []
    findings: list[Finding] = []
    for item in report.findings:
        findings.append(  # noqa: PERF401
            Finding(
                rule_id=item.rule_id,
                category="managed-key",
                title=f"Embedded managed credential in {item.type_name}::{item.field_name}",
                severity=_SEVERITY.get(item.severity, Severity.MEDIUM),
                description=(
                    f"A {item.confidence}-confidence embedded credential constant "
                    f"({item.byte_length} bytes) was found in a Xamarin/.NET assembly. "
                    "The raw value is redacted."
                ),
                evidence=(
                    f"source: {item.source}",
                    f"read by: {', '.join(item.used_by)}",
                    f"sha256: {item.fingerprint}",
                    item.evidence,
                ),
                cwe=item.cwe,
                masvs="MASVS-CRYPTO-1",
                verify="Review the assembly field and its consuming methods for key use.",
            ),
        )
    scanned = sum(1 for c in report.coverage if c.status == "scanned")
    incomplete = [c for c in report.coverage if c.status != "scanned"]
    if incomplete:
        ctx.note(
            "managed-keys",
            "partial",
            f"{scanned} assemblies scanned; {len(incomplete)} not scanned "
            f"(e.g. {incomplete[0].source}: {incomplete[0].detail})",
        )
    else:
        ctx.note("managed-keys", "ok", f"{scanned} managed assemblies scanned")
    return findings
