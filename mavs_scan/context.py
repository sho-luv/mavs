"""Shared state passed to every analyzer during a scan.

The context computes expensive artifacts once (the DEX string pool, the joined
search blob) so each analyzer reuses them instead of re-parsing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from mavs_scan import dex
from mavs_scan.apk import LoadedApk
from mavs_scan.model import Coverage

Status = Literal["ok", "partial", "unsupported", "error"]


@dataclass(slots=True)
class ScanContext:
    """Everything an analyzer needs about one loaded package."""

    apk: LoadedApk
    package: str = "the.app.package"
    app_name: str = "app"
    coverage: list[Coverage] = field(default_factory=list)
    _strings: list[str] | None = field(default=None, repr=False)
    _blob: str | None = field(default=None, repr=False)

    @property
    def dex_strings(self) -> list[str]:
        """Return the de-duplicated DEX string pool, parsed once and cached."""
        if self._strings is None:
            self._strings = dex.extract_all_strings(self.apk.dex_blobs())
        return self._strings

    @property
    def dex_blob(self) -> str:
        """Return the DEX string pool joined for fast substring search."""
        if self._blob is None:
            self._blob = "\n".join(self.dex_strings)
        return self._blob

    def note(self, stage: str, status: Status, detail: str) -> None:
        """Record a coverage note for a scan stage."""
        self.coverage.append(Coverage(stage=stage, status=status, detail=detail))
