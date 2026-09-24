"""Values crossing the archive, metadata and reporting boundaries."""

from dataclasses import dataclass, field
from typing import ClassVar, Literal

from pydantic import BaseModel, ConfigDict


@dataclass(frozen=True, slots=True)
class Assembly:
    """An unexecuted managed-code candidate from an archive."""

    source: str
    data: bytes = field(repr=False)


class ScanError(Exception):
    """A bounded input or metadata parser could not complete inspection."""

    def __init__(self, detail: str) -> None:
        """Expose a redacted diagnostic at the CLI coverage boundary."""
        self.detail: str = detail
        super().__init__(detail)


class UnsupportedFormat(ScanError):  # noqa: N818
    """Input needs a parser that this managed-code check does not provide."""


class Finding(BaseModel):
    """Evidence identifies a constant without exposing its value."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    rule_id: Literal["MAVS-KEY-001"] = "MAVS-KEY-001"
    cwe: Literal["CWE-798"] = "CWE-798"
    source: str
    type_name: str
    field_name: str
    byte_length: int
    fingerprint: str
    used_by: tuple[str, ...]
    confidence: Literal["high", "medium"]
    severity: Literal["high", "medium"]
    evidence: str


class Coverage(BaseModel):
    """Explicit per-source coverage prevents an unsupported input looking clean."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    source: str
    status: Literal["scanned", "unsupported", "error"]
    detail: str


class ScanReport(BaseModel):
    """Machine-readable managed-key inspection results."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    schema_version: Literal[1] = 1
    input: str
    sha256: str
    scope: str = "Managed .NET constants only; no runtime exploitability test."
    findings: tuple[Finding, ...]
    coverage: tuple[Coverage, ...]
