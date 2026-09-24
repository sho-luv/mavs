"""Manifest misconfiguration analysis.

Covers the legacy Bash checks (debuggable, backups, cleartext, snapshots) and
adds MobSF-style component export analysis. Cleartext and snapshot severities are
calibrated against the target SDK default to reduce false positives while keeping
the original checks and their exploitation guidance.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from mavs_scan import guidance
from mavs_scan.apk import android_attr
from mavs_scan.context import ScanContext
from mavs_scan.model import Finding, Severity

_COMPONENTS = ("activity", "activity-alias", "service", "receiver", "provider")
_LAUNCHER = "android.intent.category.LAUNCHER"


def _is_exported(elem: ET.Element, tag: str) -> bool:
    explicit = android_attr(elem, "exported")
    if explicit is not None:
        return explicit == "true"
    has_filter = elem.find("intent-filter") is not None
    if tag == "provider":
        return True
    return has_filter


def _is_launcher(elem: ET.Element) -> bool:
    return any(android_attr(cat, "name") == _LAUNCHER for cat in elem.iter("category"))


def analyze(ctx: ScanContext) -> list[Finding]:
    """Return manifest findings for ``ctx``."""
    root = ctx.apk.manifest_root
    if root is None:
        ctx.note("manifest-analysis", "unsupported", "manifest not decoded")
        return []
    findings: list[Finding] = []
    app = root.find("application")
    target_sdk = _target_sdk(root)

    if app is not None:
        findings.extend(_application_flags(ctx, app, target_sdk))
        findings.extend(_components(ctx, app))
    findings.extend(_min_sdk(root))
    ctx.note("manifest-analysis", "ok", "manifest analyzed")
    return findings


def _target_sdk(root: ET.Element) -> int | None:
    uses = root.find("uses-sdk")
    if uses is None:
        return None
    value = android_attr(uses, "targetSdkVersion")
    return int(value) if value and value.isdigit() else None


def _min_sdk(root: ET.Element) -> list[Finding]:
    uses = root.find("uses-sdk")
    if uses is None:
        return []
    value = android_attr(uses, "minSdkVersion")
    if not (value and value.isdigit()):
        return []
    min_sdk = int(value)
    if min_sdk >= 24:
        return []
    return [
        Finding(
            rule_id="MAVS-MANIFEST-MINSDK",
            category="manifest",
            title=f"Low minimum SDK ({min_sdk})",
            severity=Severity.LOW if min_sdk >= 21 else Severity.MEDIUM,
            description=(
                f"minSdkVersion is {min_sdk}. Older Android releases lack modern "
                "platform mitigations and receive no security patches."
            ),
            evidence=(f"android:minSdkVersion={min_sdk}",),
            cwe="CWE-1104",
            masvs="MASVS-PLATFORM-1",
        ),
    ]


def _application_flags(ctx: ScanContext, app: ET.Element, target_sdk: int | None) -> list[Finding]:
    findings: list[Finding] = []
    debuggable = android_attr(app, "debuggable")
    if debuggable == "true":
        findings.append(
            Finding(
                rule_id="MAVS-MANIFEST-DEBUG",
                category="manifest",
                title="Debugging enabled",
                severity=Severity.HIGH,
                description='android:debuggable="true" ships a debuggable build.',
                evidence=('android:debuggable="true"',),
                cwe="CWE-489",
                masvs="MASVS-RESILIENCE-4",
                verify="Confirm the flag in AndroidManifest.xml of the release build.",
                exploit=guidance.fill(
                    guidance.DEBUG_EXPLOIT,
                    package=ctx.package,
                    app=ctx.app_name,
                ),
            ),
        )
    backup = android_attr(app, "allowBackup")
    if backup != "false":
        findings.append(
            Finding(
                rule_id="MAVS-MANIFEST-BACKUP",
                category="manifest",
                title="Application backups allowed",
                severity=Severity.MEDIUM,
                description=(
                    "android:allowBackup is not set to false, so app data can be "
                    "extracted via adb backup without root."
                ),
                evidence=(
                    'android:allowBackup="true"'
                    if backup == "true"
                    else "allowBackup not set to false (defaults to true)",
                ),
                cwe="CWE-530",
                masvs="MASVS-STORAGE-2",
                verify="Check for android:allowBackup in the manifest application tag.",
                exploit=guidance.fill(
                    guidance.BACKUP_EXPLOIT,
                    package=ctx.package,
                    app=ctx.app_name,
                ),
            ),
        )
    findings.extend(_cleartext(ctx, app, target_sdk))
    findings.extend(_snapshots(ctx, app))
    return findings


def _cleartext(ctx: ScanContext, app: ET.Element, target_sdk: int | None) -> list[Finding]:
    cleartext = android_attr(app, "usesCleartextTraffic")
    if cleartext == "false":
        return []
    if cleartext == "true":
        severity = Severity.HIGH
        detail = 'android:usesCleartextTraffic="true"'
    elif target_sdk is not None and target_sdk >= 28:
        severity = Severity.INFO
        detail = f"not set; default-deny for targetSdk {target_sdk}"
    else:
        severity = Severity.MEDIUM
        detail = "usesCleartextTraffic not set to false; default permits cleartext"
    return [
        Finding(
            rule_id="MAVS-MANIFEST-CLEARTEXT",
            category="manifest",
            title="Cleartext traffic may be permitted",
            severity=severity,
            description=(
                "The app may allow unencrypted HTTP. Cleartext traffic can be sniffed "
                "or modified on the network path."
            ),
            evidence=(detail,),
            cwe="CWE-319",
            masvs="MASVS-NETWORK-1",
            verify="Check usesCleartextTraffic and any network security config.",
            exploit=guidance.fill(
                guidance.CLEARTEXT_EXPLOIT,
                package=ctx.package,
                app=ctx.app_name,
            ),
        ),
    ]


def _snapshots(ctx: ScanContext, app: ET.Element) -> list[Finding]:
    for activity in app.iter("activity"):
        if android_attr(activity, "excludeFromRecents") == "true":
            return []
    blob = ctx.dex_blob
    if "Landroid/view/WindowManager$LayoutParams;" in blob and "FLAG_SECURE" in blob:
        return []
    return [
        Finding(
            rule_id="MAVS-MANIFEST-SNAPSHOT",
            category="manifest",
            title="Screenshots and task snapshots allowed",
            severity=Severity.LOW,
            description=(
                "No FLAG_SECURE and no excludeFromRecents were found, so the OS may "
                "capture snapshots of sensitive screens for the recents view."
            ),
            evidence=("FLAG_SECURE / excludeFromRecents not detected",),
            cwe="CWE-200",
            masvs="MASVS-PLATFORM-3",
            verify="Background the app on a sensitive screen and inspect the snapshot.",
            exploit=guidance.fill(guidance.SNAPSHOT_EXPLOIT, package=ctx.package, app=ctx.app_name),
        ),
    ]


def _components(ctx: ScanContext, app: ET.Element) -> list[Finding]:
    findings: list[Finding] = []
    for tag in _COMPONENTS:
        for elem in app.iter(tag):
            name = android_attr(elem, "name") or "?"
            if not _is_exported(elem, tag):
                continue
            if tag in {"activity", "activity-alias"} and _is_launcher(elem):
                continue
            permission = android_attr(elem, "permission") or android_attr(elem, "readPermission")
            if permission:
                continue
            severity = Severity.HIGH if tag == "provider" else Severity.MEDIUM
            findings.append(
                Finding(
                    rule_id=f"MAVS-MANIFEST-EXPORTED-{tag.upper().replace('-', '')}",
                    category="manifest",
                    title=f"Exported {tag} without permission",
                    severity=severity,
                    description=(
                        f"The {tag} {name} is exported and not protected by a "
                        "permission, so any app on the device can invoke it."
                    ),
                    evidence=(name,),
                    cwe="CWE-926",
                    masvs="MASVS-PLATFORM-1",
                    verify=(
                        f"Invoke it from another app or adb, e.g. "
                        f"adb shell am start -n {ctx.package}/{name}"
                        if tag in {"activity", "activity-alias"}
                        else f"Interact with exported {tag} {name} via an explicit intent."
                    ),
                ),
            )
    return findings
