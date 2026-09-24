"""Hardcoded key-material and secret detection.

Preserves the legacy bundled-``.pem`` check and adds embedded private keys and
common credential token formats found in code strings and small text resources.
Values are reported by location and type; raw secret bytes are not printed.
"""

from __future__ import annotations

import re

from mavs_scan import guidance
from mavs_scan.context import ScanContext
from mavs_scan.model import Finding, Severity

_KEY_FILE_EXT = (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".bks", ".der")
_MAX_TEXT = 2_000_000
_MAX_TEXT_FILES = 400

_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("private-key", "PEM private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws-access-key", "AWS access key id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("google-api-key", "Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("slack-token", "Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}")),
    ("stripe-key", "Stripe secret key", re.compile(r"sk_live_[0-9A-Za-z]{16,}")),
    ("github-token", "GitHub token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}")),
)


def analyze(ctx: ScanContext) -> list[Finding]:
    """Return findings for bundled key files and embedded secrets."""
    findings: list[Finding] = []
    findings.extend(_key_files(ctx))
    findings.extend(_embedded_secrets(ctx))
    ctx.note("secrets", "ok", "key files and secret patterns reviewed")
    return findings


def _key_files(ctx: ScanContext) -> list[Finding]:
    hits = [n for n in ctx.apk.names() if n.lower().endswith(_KEY_FILE_EXT)]
    if not hits:
        return []
    return [
        Finding(
            rule_id="MAVS-SECRET-KEYFILE",
            category="secret",
            title="Bundled key or certificate file",
            severity=Severity.MEDIUM,
            description=(
                "The package bundles key or certificate files. If any contains a "
                "private key, embedding it lets an attacker decrypt or impersonate."
            ),
            evidence=tuple(hits[:40]),
            cwe="CWE-312",
            masvs="MASVS-STORAGE-1",
            verify="Inspect each bundled file for private key or credential material.",
            exploit=guidance.fill(guidance.PEM_EXPLOIT, package=ctx.package, app=ctx.app_name),
        ),
    ]


def _embedded_secrets(ctx: ScanContext) -> list[Finding]:
    haystack = ctx.dex_blob + "\n" + _resource_text(ctx)
    findings: list[Finding] = []
    for kind, title, pattern in _PATTERNS:
        matches = pattern.findall(haystack)
        if not matches:
            continue
        high = {"private-key", "aws-access-key", "stripe-key"}
        severity = Severity.HIGH if kind in high else Severity.MEDIUM
        findings.append(
            Finding(
                rule_id=f"MAVS-SECRET-{kind.upper().replace('-', '')}",
                category="secret",
                title=f"Embedded {title}",
                severity=severity,
                description=(
                    f"A {title} pattern appears in the package. Confirm it is a live "
                    "credential and not a placeholder or public value."
                ),
                evidence=(f"{len(set(matches))} match(es) for {title}",),
                cwe="CWE-798",
                masvs="MASVS-STORAGE-1",
                verify=f"Locate the {title} in code or resources and test its validity.",
            ),
        )
    return findings


def _resource_text(ctx: ScanContext) -> str:
    parts: list[str] = []
    total = 0
    count = 0
    for name in ctx.apk.names():
        if count >= _MAX_TEXT_FILES or total >= _MAX_TEXT:
            break
        if not name.endswith((".xml", ".json", ".properties", ".txt", ".js", ".cfg")):
            continue
        if name == "AndroidManifest.xml":
            continue
        data = ctx.apk.read(name)
        if data is None:
            continue
        count += 1
        total += len(data)
        parts.append(data.decode("utf-8", errors="replace"))
    return "\n".join(parts)
