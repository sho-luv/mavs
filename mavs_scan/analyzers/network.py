"""Network security config analysis and endpoint extraction.

Decodes any binary ``res/xml`` network security configuration to flag cleartext
permits and user-CA trust, and extracts domains, URLs and emails from the DEX
string pool for reconnaissance context.
"""

from __future__ import annotations

import io
import re
import xml.etree.ElementTree as ET

import defusedxml.ElementTree as DET
from apkInspector.axml import get_manifest

from mavs_scan.context import ScanContext
from mavs_scan.model import Finding, Severity

_URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,200}")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}")
_FIREBASE_RE = re.compile(r"https://[A-Za-z0-9.-]+\.firebaseio\.com")
_MAX_LIST = 40


def analyze(ctx: ScanContext) -> list[Finding]:
    """Return network configuration and endpoint findings for ``ctx``."""
    findings: list[Finding] = []
    findings.extend(_network_config(ctx))
    findings.extend(_endpoints(ctx))
    ctx.note("network", "ok", "network config and endpoints reviewed")
    return findings


def _network_config(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for name in ctx.apk.names():
        if not (name.startswith("res/") and name.endswith(".xml")):
            continue
        data = ctx.apk.read(name)
        if data is None or b"network-security-config" not in _peek(data):
            continue
        root = _decode_xml(data)
        if root is None or root.tag != "network-security-config":
            continue
        findings.extend(_scan_config(root))
    return findings


def _peek(data: bytes) -> bytes:
    try:
        return get_manifest(io.BytesIO(data)).encode("utf-8", errors="replace")
    except (ValueError, OSError, RuntimeError):
        return b""


def _decode_xml(data: bytes) -> ET.Element | None:
    try:
        text = get_manifest(io.BytesIO(data))
        return DET.fromstring(text)
    except (ValueError, OSError, RuntimeError, ET.ParseError):
        return None


def _scan_config(root: ET.Element) -> list[Finding]:
    findings: list[Finding] = []
    for node in root.iter():
        if node.get("cleartextTrafficPermitted") == "true":
            findings.append(
                Finding(
                    rule_id="MAVS-NET-CLEARTEXT-CFG",
                    category="network",
                    title="Network security config permits cleartext",
                    severity=Severity.HIGH,
                    description=(
                        "A domain-config or base-config sets "
                        'cleartextTrafficPermitted="true", allowing plaintext HTTP.'
                    ),
                    evidence=(f'<{node.tag} cleartextTrafficPermitted="true">',),
                    cwe="CWE-319",
                    masvs="MASVS-NETWORK-1",
                ),
            )
        for anchor in node.findall("trust-anchors/certificates"):
            if anchor.get("src") == "user":
                findings.append(  # noqa: PERF401
                    Finding(
                        rule_id="MAVS-NET-USERCA",
                        category="network",
                        title="Trusts user-installed CA certificates",
                        severity=Severity.MEDIUM,
                        description=(
                            "The network security config trusts user CAs, which eases "
                            "interception with a proxy certificate."
                        ),
                        evidence=('<certificates src="user"/>',),
                        cwe="CWE-295",
                        masvs="MASVS-NETWORK-2",
                    ),
                )
    return findings


def _endpoints(ctx: ScanContext) -> list[Finding]:
    blob = ctx.dex_blob
    if not blob:
        return []
    findings: list[Finding] = []
    urls = sorted(set(_URL_RE.findall(blob)))
    http_urls = [u for u in urls if u.startswith("http://")]
    emails = sorted({e for e in _EMAIL_RE.findall(blob) if not e.endswith((".png", ".jpg"))})
    firebase = sorted(set(_FIREBASE_RE.findall(blob)))
    if http_urls:
        findings.append(
            Finding(
                rule_id="MAVS-NET-HTTPURL",
                category="network",
                title="Cleartext HTTP URLs referenced in code",
                severity=Severity.MEDIUM,
                description="Hardcoded http:// URLs were found and may carry sensitive traffic.",
                evidence=tuple(http_urls[:_MAX_LIST]),
                cwe="CWE-319",
                masvs="MASVS-NETWORK-1",
            ),
        )
    if firebase:
        findings.append(
            Finding(
                rule_id="MAVS-NET-FIREBASE",
                category="network",
                title="Firebase database endpoints referenced",
                severity=Severity.INFO,
                description=(
                    "Firebase Realtime Database URLs were found. Test whether the "
                    "database is readable without authentication (append /.json)."
                ),
                evidence=tuple(firebase[:_MAX_LIST]),
                masvs="MASVS-NETWORK-1",
            ),
        )
    if urls or emails:
        findings.append(
            Finding(
                rule_id="MAVS-NET-ENDPOINTS",
                category="network",
                title=f"Extracted {len(urls)} URL(s) and {len(emails)} email(s)",
                severity=Severity.INFO,
                description="Endpoints and emails recovered from the code for reconnaissance.",
                evidence=tuple(urls[:_MAX_LIST]) + tuple(f"email: {e}" for e in emails[:_MAX_LIST]),
            ),
        )
    return findings
