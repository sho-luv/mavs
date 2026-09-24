"""Requested-permission risk analysis based on the permission risk map."""

from __future__ import annotations

from mavs_scan.apk import android_attr
from mavs_scan.context import ScanContext
from mavs_scan.data.permissions import PERMISSION_RISK
from mavs_scan.model import Finding, Severity


def requested_permissions(ctx: ScanContext) -> tuple[str, ...]:
    """Return the sorted set of permissions requested in the manifest."""
    root = ctx.apk.manifest_root
    if root is None:
        return ()
    names: set[str] = set()
    for tag in ("uses-permission", "uses-permission-sdk-23"):
        for elem in root.iter(tag):
            name = android_attr(elem, "name")
            if name:
                names.add(name)
    return tuple(sorted(names))


def analyze(ctx: ScanContext) -> list[Finding]:
    """Return one finding per requested permission that carries notable risk."""
    perms = requested_permissions(ctx)
    if ctx.apk.manifest_root is None:
        ctx.note("permissions", "unsupported", "manifest not decoded")
        return []
    findings: list[Finding] = []
    for perm in perms:
        entry = PERMISSION_RISK.get(perm)
        if entry is None:
            continue
        severity, reason = entry
        if severity < Severity.MEDIUM:
            continue
        findings.append(
            Finding(
                rule_id="MAVS-PERM",
                category="permission",
                title=f"Dangerous permission: {perm.rsplit('.', 1)[-1]}",
                severity=severity,
                description=reason,
                evidence=(perm,),
                cwe="CWE-250",
                masvs="MASVS-PLATFORM-1",
            ),
        )
    ctx.note("permissions", "ok", f"{len(perms)} permission(s) reviewed")
    return findings
