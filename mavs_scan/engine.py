"""Scan orchestration: load a package, run every analyzer, build the report."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal

from mavs_scan import apk as apk_loader
from mavs_scan.analyzers import ANALYZERS
from mavs_scan.analyzers.permissions import requested_permissions
from mavs_scan.apk import android_attr
from mavs_scan.context import ScanContext
from mavs_scan.model import AppInfo, Coverage, Finding, ScanReport


def _app_info(ctx: ScanContext) -> AppInfo:
    root = ctx.apk.manifest_root
    if root is None:
        return AppInfo()
    uses = root.find("uses-sdk")
    min_sdk = android_attr(uses, "minSdkVersion") if uses is not None else None
    target_sdk = android_attr(uses, "targetSdkVersion") if uses is not None else None
    return AppInfo(
        package=root.get("package"),
        version_name=android_attr(root, "versionName"),
        version_code=android_attr(root, "versionCode"),
        min_sdk=int(min_sdk) if min_sdk and min_sdk.isdigit() else None,
        target_sdk=int(target_sdk) if target_sdk and target_sdk.isdigit() else None,
        main_activity=_main_activity(ctx),
        permissions=requested_permissions(ctx),
    )


def _main_activity(ctx: ScanContext) -> str | None:
    root = ctx.apk.manifest_root
    app = root.find("application") if root is not None else None
    if app is None:
        return None
    for activity in list(app.iter("activity")) + list(app.iter("activity-alias")):
        for cat in activity.iter("category"):
            if android_attr(cat, "name") == "android.intent.category.LAUNCHER":
                return android_attr(activity, "name")
    return None


def scan(path: Path, *, managed_keys: bool = True) -> ScanReport:
    """Run a full static scan of the APK/XAPK at ``path`` and return the report.

    Args:
        path: The APK or XAPK to scan.
        managed_keys: Run the deep Xamarin/.NET managed-key inspection. It is the
            slowest stage; disable it for a fast pass over other checks.
    """
    raw = path.read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()
    loaded = apk_loader.load(path)
    ctx = ScanContext(apk=loaded)
    ctx.coverage.extend(loaded.coverage)
    if loaded.manifest_root is not None:
        ctx.package = loaded.manifest_root.get("package") or ctx.package
    info = _app_info(ctx)
    ctx.app_name = (info.package or "app").rsplit(".", 1)[-1]

    analyzers = (
        ANALYZERS
        if managed_keys
        else tuple(a for a in ANALYZERS if a.__module__.rsplit(".", 1)[-1] != "managed_keys")
    )
    findings: list[Finding] = []
    for analyzer in analyzers:
        try:
            findings.extend(analyzer(ctx))
        except Exception as exc:  # noqa: BLE001 - one analyzer must not abort the scan
            ctx.note(analyzer.__module__.rsplit(".", 1)[-1], "error", f"analyzer failed: {exc}")

    findings.sort(key=lambda f: (-int(f.severity), f.category, f.rule_id))
    file_type: Literal["apk", "xapk", "unknown"] = (
        "apk" if loaded.file_type == "apk" else "xapk" if loaded.file_type == "xapk" else "unknown"
    )
    return ScanReport(
        target=str(path),
        file_type=file_type,
        sha256=sha256,
        size_bytes=len(raw),
        app=info,
        findings=tuple(findings),
        coverage=tuple(_dedupe_coverage(ctx.coverage)),
    )


def _dedupe_coverage(items: list[Coverage]) -> list[Coverage]:
    seen: set[tuple[str, str, str]] = set()
    out: list[Coverage] = []
    for item in items:
        key = (item.stage, item.status, item.detail)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out
