"""Gated end-to-end scans against real KARR samples.

These require a real binary AndroidManifest.xml and signing block, so they run
only when ``MAVS_KARR_DIR`` points at a directory holding the separately obtained
``karr-security-0.80-base.apk`` and ``karr-security-0.80.xapk``. They do not
download, install or execute the applications, and no sample is committed.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final

import pytest

from mavs_scan.engine import scan
from mavs_scan.model import ScanReport, Severity

SAMPLE_DIR: Final = os.environ.get("MAVS_KARR_DIR")
APK_NAME: Final = "karr-security-0.80-base.apk"
XAPK_NAME: Final = "karr-security-0.80.xapk"
PACKAGE: Final = "com.whgos.swdscustomerapp"


def _sample(name: str) -> Path | None:
    if SAMPLE_DIR is None:
        return None
    path = Path(SAMPLE_DIR) / name
    return path if path.exists() else None


@pytest.fixture(scope="session")
def apk_report() -> ScanReport:
    path = _sample(APK_NAME)
    if path is None:
        pytest.skip(f"Set MAVS_KARR_DIR to a directory containing {APK_NAME}")
    return scan(path, managed_keys=True)


def test_apk_identity_and_grade(apk_report: ScanReport) -> None:
    assert apk_report.file_type == "apk"
    assert apk_report.app.package == PACKAGE
    assert apk_report.app.min_sdk is not None
    assert apk_report.app.target_sdk is not None
    assert apk_report.app.permissions
    assert apk_report.risk_score > 0
    assert apk_report.grade in {"C", "D", "F"}


def test_apk_reports_expected_findings(apk_report: ScanReport) -> None:
    ids = {f.rule_id for f in apk_report.findings}
    # Legacy checks preserved through the port.
    assert "MAVS-CODE-HOSTNAME" in ids
    assert "MAVS-MANIFEST-BACKUP" in ids
    # New MobSF-style coverage.
    assert "MAVS-FRAMEWORK" in ids
    framework = next(f for f in apk_report.findings if f.rule_id == "MAVS-FRAMEWORK")
    assert "Xamarin/.NET" in framework.evidence
    # Managed-key detection folded into the unified report.
    assert "MAVS-KEY-001" in ids
    key = next(f for f in apk_report.findings if f.rule_id == "MAVS-KEY-001")
    assert key.severity is Severity.HIGH
    assert key.category == "managed-key"


def test_apk_signing_schemes_detected(apk_report: ScanReport) -> None:
    cert_notes = [c for c in apk_report.coverage if c.stage == "certificate"]
    assert cert_notes
    assert any("v2" in c.detail or "v3" in c.detail for c in cert_notes)


def test_skip_managed_keys_omits_key_findings() -> None:
    path = _sample(APK_NAME)
    if path is None:
        pytest.skip(f"Set MAVS_KARR_DIR to a directory containing {APK_NAME}")
    report = scan(path, managed_keys=False)
    ids = {f.rule_id for f in report.findings}
    assert "MAVS-KEY-001" not in ids
    assert "MAVS-CODE-HOSTNAME" in ids  # non-managed checks still run


def test_xapk_container_scans_base_apk() -> None:
    path = _sample(XAPK_NAME)
    if path is None:
        pytest.skip(f"Set MAVS_KARR_DIR to a directory containing {XAPK_NAME}")
    report = scan(path, managed_keys=False)
    assert report.file_type == "xapk"
    assert report.app.package == PACKAGE
