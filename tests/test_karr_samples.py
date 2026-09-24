import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Final

import pytest

from mavs_keys.models import ScanReport

ROOT: Final = Path(__file__).resolve().parents[1]
SAMPLE_DIR: Final = os.environ.get("MAVS_KARR_DIR")
AUTH_TYPE: Final = "GridtraqPL.Objects.Units.QTAuth"
LICENSE_TYPE: Final = "Syncfusion.Licensing.FusionLicenseProvider"


def scan_sample(path: Path) -> ScanReport:
    result = subprocess.run(
        [str(ROOT / "mavs.sh"), "-k", "-f", str(path), "-j"],
        cwd=path.parent,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return ScanReport.model_validate_json(result.stdout)


@pytest.mark.skipif(SAMPLE_DIR is None, reason="Set MAVS_KARR_DIR to local KARR samples")
def test_real_karr_apks_and_xapks_report_the_same_two_authentication_keys(tmp_path: Path) -> None:
    assert SAMPLE_DIR is not None
    directory = Path(SAMPLE_DIR).resolve()
    paths = tuple(
        directory / f"karr-security-{version}{suffix}"
        for version in ("0.80", "0.89")
        for suffix in ("-base.apk", ".xapk")
    )
    with ThreadPoolExecutor(max_workers=4) as pool:
        reports = tuple(pool.map(scan_sample, paths))
    for path, report in zip(paths, reports, strict=True):
        report_name = (
            path.name.replace("karr-security", "mavs")
            .replace(".xapk", "-xapk.json")
            .replace(".apk", ".json")
        )
        _ = (tmp_path / report_name).write_text(report.model_dump_json(indent=2))
    assert len(tuple(tmp_path.glob("mavs-*.json"))) == 4
    fingerprints: set[tuple[str, str]] | None = None
    for report in reports:
        assert len(report.coverage) == 170
        assert all(item.status == "scanned" for item in report.coverage)
        assert len(report.findings) == 3
        assert {(item.type_name, item.field_name) for item in report.findings} == {
            (AUTH_TYPE, "Dealer_Key"),
            (AUTH_TYPE, "Customer_Key"),
            (LICENSE_TYPE, "privateKey"),
        }
        auth = tuple(item for item in report.findings if item.type_name == AUTH_TYPE)
        assert len(auth) == 2
        for item in auth:
            assert item.byte_length == 16
            assert item.confidence == "high"
            assert item.used_by == (f"{AUTH_TYPE}::GenerateHash",)
        license_key = next(item for item in report.findings if item.type_name == LICENSE_TYPE)
        assert license_key.byte_length == 22
        assert license_key.confidence == "medium"
        assert set(license_key.used_by) == {
            f"{LICENSE_TYPE}::ExtractBase64LicenseKey",
            f"{LICENSE_TYPE}::GenerateBase64LicenseKey",
        }
        current = {(item.field_name, item.fingerprint) for item in auth}
        if fingerprints is None:
            fingerprints = current
        assert current == fingerprints
