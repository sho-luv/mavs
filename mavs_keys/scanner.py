"""Aggregate findings and explicit coverage into a redacted report."""

import hashlib
from pathlib import Path

from mavs_keys.archives import MAX_INPUT, load_assemblies
from mavs_keys.managed import inspect_assembly
from mavs_keys.models import Coverage, Finding, ScanError, ScanReport, UnsupportedFormat


def scan(path: Path) -> ScanReport:
    """Inspect an APK/XAPK, preserving incomplete coverage as report evidence."""
    digest = ""
    findings: list[Finding] = []
    coverage: list[Coverage] = []
    try:
        if path.stat().st_size > MAX_INPUT:
            raise ScanError("input exceeds the supported file-size limit")
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        assemblies = load_assemblies(path)
        for assembly in assemblies:
            try:
                findings.extend(inspect_assembly(assembly))
                coverage.append(
                    Coverage(
                        source=assembly.source,
                        status="scanned",
                        detail="Supported managed constant patterns inspected",
                    )
                )
            except UnsupportedFormat as error:
                coverage.append(
                    Coverage(source=assembly.source, status="unsupported", detail=error.detail)
                )
            except ScanError as error:
                coverage.append(
                    Coverage(source=assembly.source, status="error", detail=error.detail)
                )
    except UnsupportedFormat as error:
        coverage.append(Coverage(source=str(path), status="unsupported", detail=error.detail))
    except ScanError as error:
        coverage.append(Coverage(source=str(path), status="error", detail=error.detail))
    except OSError:
        coverage.append(Coverage(source=str(path), status="error", detail="Cannot read input file"))
    return ScanReport(
        input=str(path), sha256=digest, findings=tuple(findings), coverage=tuple(coverage)
    )
