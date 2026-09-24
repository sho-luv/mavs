"""Typed results shared across analyzers, the engine and reporters.

Findings never assert runtime exploitability. A static observation records what
is present in the package and how a tester can confirm or exploit it by hand.
"""

from __future__ import annotations

from enum import IntEnum
from typing import ClassVar, Literal

from pydantic import BaseModel, ConfigDict

Category = Literal[
    "manifest",
    "permission",
    "certificate",
    "code",
    "network",
    "binary",
    "tracker",
    "secret",
    "managed-key",
]


class Severity(IntEnum):
    """Ordered severity so findings sort worst-first and roll up to a score."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        """Return the lowercase name used in text and JSON output."""
        return self.name.lower()


SEVERITY_BY_NAME: dict[str, Severity] = {s.name.lower(): s for s in Severity}


class Finding(BaseModel):
    """One static observation with evidence and manual verification guidance."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    rule_id: str
    category: Category
    title: str
    severity: Severity
    description: str
    evidence: tuple[str, ...] = ()
    cwe: str | None = None
    masvs: str | None = None
    reference: str | None = None
    verify: str | None = None
    exploit: str | None = None


class Coverage(BaseModel):
    """Explicit per-stage coverage so an unparsed input never looks clean."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    stage: str
    status: Literal["ok", "partial", "unsupported", "error"]
    detail: str


class AppInfo(BaseModel):
    """Identity extracted from the manifest and signing block."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    package: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    main_activity: str | None = None
    permissions: tuple[str, ...] = ()


class ScanReport(BaseModel):
    """Machine-readable result of a full static package scan."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    schema_version: Literal[2] = 2
    tool: str = "mavs"
    target: str
    file_type: Literal["apk", "xapk", "unknown"]
    sha256: str
    size_bytes: int
    app: AppInfo
    findings: tuple[Finding, ...]
    coverage: tuple[Coverage, ...]

    @property
    def risk_score(self) -> int:
        """Return a 0-100 risk score weighted by finding severity.

        The score is a triage aid, not a certification. Zero findings yields
        zero and never implies the application is secure.
        """
        weights = {
            Severity.CRITICAL: 40,
            Severity.HIGH: 20,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }
        total = sum(weights[f.severity] for f in self.findings)
        return min(total, 100)

    @property
    def grade(self) -> str:
        """Return a coarse letter grade derived from the risk score."""
        score = self.risk_score
        if score >= 60:
            return "F"
        if score >= 40:
            return "D"
        if score >= 20:
            return "C"
        if score >= 8:
            return "B"
        return "A"

    def counts(self) -> dict[str, int]:
        """Return finding counts keyed by lowercase severity label."""
        out = {s.label: 0 for s in Severity}
        for finding in self.findings:
            out[finding.severity.label] += 1
        return out
