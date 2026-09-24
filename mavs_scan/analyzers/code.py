"""Pattern-based code analysis over the DEX string pool.

Runs the rule set in ``data.code_rules`` and attaches the legacy exploitation
guidance for the certificate-validation and logging findings so nothing from the
original tool is lost.
"""

from __future__ import annotations

from mavs_scan import guidance
from mavs_scan.context import ScanContext
from mavs_scan.data.code_rules import RULES
from mavs_scan.model import Finding

_MAX_EVIDENCE = 5
_EVIDENCE_LEN = 160

_EXPLOIT_BY_RULE: dict[str, str] = {
    "MAVS-CODE-HOSTNAME": guidance.CERT_VALIDATION_EXPLOIT,
    "MAVS-CODE-PROTSPACE": guidance.CERT_VALIDATION_EXPLOIT,
    "MAVS-CODE-TRUSTALL": guidance.CERT_VALIDATION_EXPLOIT,
    "MAVS-CODE-SSLERROR": guidance.CERT_VALIDATION_EXPLOIT,
    "MAVS-CODE-LOG": guidance.LOGGING_EXPLOIT,
}


def analyze(ctx: ScanContext) -> list[Finding]:
    """Return code findings for every rule whose patterns match ``ctx``."""
    if not ctx.dex_strings:
        ctx.note("code", "partial", "no DEX strings extracted")
        return []
    blob = ctx.dex_blob
    findings: list[Finding] = []
    for rule in RULES:
        matched = [pat for pat in rule.patterns if pat in blob]
        if not matched:
            continue
        evidence = _evidence(ctx.dex_strings, matched)
        exploit = _EXPLOIT_BY_RULE.get(rule.rule_id)
        findings.append(
            Finding(
                rule_id=rule.rule_id,
                category="code",
                title=rule.title,
                severity=rule.severity,
                description=rule.description,
                evidence=tuple(evidence),
                cwe=rule.cwe,
                masvs=rule.masvs,
                reference=rule.reference,
                verify=f"Search decompiled code for: {', '.join(matched)}",
                exploit=guidance.fill(exploit, package=ctx.package, app=ctx.app_name),
            ),
        )
    ctx.note("code", "ok", f"{len(RULES)} rules over {len(ctx.dex_strings)} strings")
    return findings


def _evidence(strings: list[str], patterns: list[str]) -> list[str]:
    out: list[str] = []
    for pat in patterns:
        for s in strings:
            if pat in s:
                snippet = s.strip().replace("\n", " ")[:_EVIDENCE_LEN]
                out.append(snippet)
                break
        if len(out) >= _MAX_EVIDENCE:
            break
    return out
