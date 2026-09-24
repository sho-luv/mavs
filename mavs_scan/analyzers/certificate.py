"""Signing certificate analysis using asn1crypto.

Reports the signing scheme set and weak signature algorithms. The APK signing
certificate is self-signed by design, so that alone is not flagged.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from mavs_scan.context import ScanContext
from mavs_scan.model import Finding, Severity

if TYPE_CHECKING:
    from collections.abc import Iterable

_WEAK_SIG = ("md5", "sha1")


def _summarize(der: bytes) -> tuple[str, str]:
    from asn1crypto import x509  # noqa: PLC0415

    cert = x509.Certificate.load(der)
    sig_algo = cert["signature_algorithm"].signature_algo
    hash_algo = ""
    try:
        hash_algo = cert["signature_algorithm"].hash_algo or ""
    except (ValueError, KeyError):
        hash_algo = ""
    fingerprint = hashlib.sha256(der).hexdigest()
    return f"{hash_algo}with{sig_algo}".lower(), fingerprint


def analyze(ctx: ScanContext) -> list[Finding]:
    """Return signing certificate findings for ``ctx``."""
    certs, schemes = ctx.apk.certificates()
    if not certs and not schemes:
        ctx.note("certificate", "partial", "no signing certificate recovered")
        return []
    findings: list[Finding] = []
    findings.extend(_scheme_findings(schemes))
    findings.extend(_weak_signature(certs))
    ctx.note("certificate", "ok", f"schemes={','.join(schemes) or 'none'}; certs={len(certs)}")
    return findings


def _scheme_findings(schemes: Iterable[str]) -> list[Finding]:
    scheme_set = set(schemes)
    if scheme_set and scheme_set <= {"v1"}:
        return [
            Finding(
                rule_id="MAVS-CERT-V1ONLY",
                category="certificate",
                title="Signed only with the v1 (JAR) scheme",
                severity=Severity.MEDIUM,
                description=(
                    "The APK uses only v1 signing. v1-only packages are exposed to the "
                    "Janus (CVE-2017-13156) tampering class on older Android and lack "
                    "the integrity guarantees of v2/v3."
                ),
                evidence=("signing schemes: v1",),
                cwe="CWE-347",
                masvs="MASVS-RESILIENCE-3",
                reference="https://nvd.nist.gov/vuln/detail/CVE-2017-13156",
            ),
        ]
    return []


def _weak_signature(certs: Iterable[bytes]) -> list[Finding]:
    findings: list[Finding] = []
    for der in certs:
        try:
            algo, fingerprint = _summarize(der)
        except (ValueError, KeyError, TypeError):
            continue
        if any(weak in algo for weak in _WEAK_SIG):
            findings.append(
                Finding(
                    rule_id="MAVS-CERT-WEAKSIG",
                    category="certificate",
                    title="Weak certificate signature algorithm",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The signing certificate uses {algo}, a weak algorithm "
                        "vulnerable to collision attacks."
                    ),
                    evidence=(f"algorithm={algo}", f"sha256={fingerprint}"),
                    cwe="CWE-327",
                    masvs="MASVS-CRYPTO-1",
                ),
            )
    return findings
