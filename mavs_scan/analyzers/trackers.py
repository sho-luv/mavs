"""Third-party tracker and ad-SDK detection from DEX type descriptors."""

from __future__ import annotations

from mavs_scan.context import ScanContext
from mavs_scan.data.trackers import TRACKERS
from mavs_scan.model import Finding, Severity


def analyze(ctx: ScanContext) -> list[Finding]:
    """Return one informational finding listing detected trackers, if any."""
    blob = ctx.dex_blob
    if not blob:
        ctx.note("trackers", "partial", "no DEX strings extracted")
        return []
    detected = sorted(
        name for name, prefixes in TRACKERS.items() if any(p in blob for p in prefixes)
    )
    ctx.note("trackers", "ok", f"{len(detected)} tracker(s) detected")
    if not detected:
        return []
    return [
        Finding(
            rule_id="MAVS-TRACKER",
            category="tracker",
            title=f"{len(detected)} third-party tracker(s)/ad SDK(s) bundled",
            severity=Severity.INFO,
            description=(
                "Bundled analytics or advertising SDKs collect device or user data. "
                "This is data-collection surface, not a vulnerability."
            ),
            evidence=tuple(detected),
            masvs="MASVS-PRIVACY-1",
        ),
    ]
