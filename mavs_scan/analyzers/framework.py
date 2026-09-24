"""Cross-platform framework detection and manual data-storage guidance.

Preserves the legacy Flutter detection (with proxying guidance) and the
device-data-storage manual check, and adds detection of other common
cross-platform runtimes for interception context.
"""

from __future__ import annotations

from mavs_scan import guidance
from mavs_scan.context import ScanContext
from mavs_scan.model import Finding, Severity


def _detect(ctx: ScanContext) -> list[str]:
    names = ctx.apk.names()
    joined = "\n".join(names)
    blob = ctx.dex_blob
    detected: list[str] = []
    if "libflutter.so" in joined or "assets/flutter_assets" in joined:
        detected.append("Flutter")
    if any(n.startswith("assemblies/") for n in names) or "Mono.Android" in blob:
        detected.append("Xamarin/.NET")
    if "libreactnativejni.so" in joined or "assets/index.android.bundle" in joined:
        detected.append("React Native")
    if "assets/www/cordova.js" in joined or "assets/www/cordova_plugins.js" in joined:
        detected.append("Cordova/PhoneGap")
    if "libunity.so" in joined:
        detected.append("Unity")
    if "assets/capacitor.config.json" in joined:
        detected.append("Capacitor")
    return detected


def analyze(ctx: ScanContext) -> list[Finding]:
    """Return framework detection and manual data-storage findings."""
    findings: list[Finding] = []
    frameworks = _detect(ctx)
    if frameworks:
        findings.append(
            Finding(
                rule_id="MAVS-FRAMEWORK",
                category="code",
                title=f"Built with {', '.join(frameworks)}",
                severity=Severity.INFO,
                description=(
                    "Cross-platform runtime detected. These frameworks route traffic "
                    "and store data differently, which affects how you intercept and "
                    "inspect the app."
                ),
                evidence=tuple(frameworks),
                exploit=(
                    guidance.fill(guidance.FLUTTER_EXPLOIT, package=ctx.package, app=ctx.app_name)
                    if "Flutter" in frameworks
                    else None
                ),
            ),
        )
    findings.append(
        Finding(
            rule_id="MAVS-STORAGE-MANUAL",
            category="code",
            title="Insecure device data storage (manual check)",
            severity=Severity.INFO,
            description=(
                "Local data storage cannot be confirmed statically. Exercise the app, "
                "then pull and inspect its private data directory for sensitive values."
            ),
            evidence=("requires a device and manual testing",),
            masvs="MASVS-STORAGE-1",
            verify="Enter identifiable test data, then inspect shared_prefs and databases.",
            exploit=guidance.fill(
                guidance.DATA_STORAGE_EXPLOIT,
                package=ctx.package,
                app=ctx.app_name,
            ),
        ),
    )
    ctx.note("framework", "ok", f"{len(frameworks)} framework(s) detected")
    return findings
