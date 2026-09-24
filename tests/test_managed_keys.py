import base64
import hashlib
import io
import struct
import subprocess
import zipfile
from pathlib import Path
from typing import ClassVar, Final, Literal

import lz4.block
import pytest
from pydantic import BaseModel, ConfigDict

ROOT: Final = Path(__file__).resolve().parents[1]
ASSEMBLY: Final = ROOT / "tests/fixtures/SyntheticFixture.dll"
DEALER: Final = bytes.fromhex("1127394b5d6f718395a7b9cbddeff113")
CUSTOMER: Final = bytes.fromhex("223446586a7c8e90a2b4c6d8eafc1e30")


class Finding(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)
    rule_id: str
    source: str
    type_name: str
    field_name: str
    byte_length: int
    fingerprint: str
    used_by: list[str]
    confidence: Literal["high", "medium"]


class Coverage(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)
    source: str
    status: Literal["scanned", "unsupported", "error"]
    detail: str


class Report(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)
    schema_version: Literal[1]
    input: str
    sha256: str
    findings: list[Finding]
    coverage: list[Coverage]


def archive(member: str, payload: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as container:
        container.writestr(member, payload)
    return buffer.getvalue()


def store(payload: bytes) -> bytes:
    header = struct.pack("<4sIIII", b"XABA", 1, 1, 0, 1)
    descriptor = struct.pack("<IIIIII", 44, len(payload), 0, 0, 0, 0)
    return header + descriptor + payload


def invoke(path: Path, *, json_output: bool = True) -> subprocess.CompletedProcess[str]:
    args = [str(ROOT / "mavs.sh"), "-k", "-f", str(path)]
    if json_output:
        args.append("-j")
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=60, check=False)


@pytest.mark.parametrize("packaging", ["ordinary", "store", "compressed", "xapk"])
def test_embedded_auth_keys_are_found_when_managed_assembly_is_packaged(
    tmp_path: Path,
    packaging: Literal["ordinary", "store", "compressed", "xapk"],
) -> None:
    # Given: an APK containing two fabricated embedded authentication keys.
    dll = ASSEMBLY.read_bytes()
    compressed = struct.pack("<4sII", b"XALZ", 0, len(dll))
    compressed += lz4.block.compress(dll, store_size=False)
    apk = {
        "ordinary": archive("assemblies/SyntheticFixture.dll", dll),
        "store": archive("assemblies/assemblies.arm64_v8a.blob", store(dll)),
        "compressed": archive("assemblies/assemblies.arm64_v8a.blob", store(compressed)),
        "xapk": archive("base.apk", archive("assemblies/SyntheticFixture.dll", dll)),
    }[packaging]
    path = tmp_path / (
        "sample with spaces.xapk" if packaging == "xapk" else "sample with spaces.apk"
    )
    _ = path.write_bytes(apk)

    # When: the public scanner entrypoint handles the real archive.
    result = invoke(path)

    # Then: only fixed keys, with usage evidence, are reported successfully.
    assert result.returncode == 0, result.stderr + result.stdout
    report = Report.model_validate_json(result.stdout)
    assert report.sha256 == hashlib.sha256(apk).hexdigest()
    assert {finding.field_name for finding in report.findings} == {
        "DealerKey",
        "CustomerKey",
    }
    for finding in report.findings:
        assert finding.rule_id == "MAVS-KEY-001"
        assert finding.type_name.endswith("DeviceAuthenticator")
        assert finding.byte_length == 16
        assert finding.fingerprint
        assert any("GenerateHash" in method for method in finding.used_by)
        assert finding.confidence == "high"
    assert report.coverage
    assert all(item.status == "scanned" for item in report.coverage)


@pytest.mark.parametrize("json_output", [True, False])
def test_key_values_are_redacted_when_report_is_rendered(tmp_path: Path, json_output: bool) -> None:
    # Given: known fabricated byte values in a managed assembly.
    path = tmp_path / "secrets.apk"
    _ = path.write_bytes(archive("assemblies/SyntheticFixture.dll", ASSEMBLY.read_bytes()))

    # When: either human-readable or machine-readable output is requested.
    result = invoke(path, json_output=json_output)

    # Then: the output identifies findings without exposing raw values.
    assert result.returncode == 0, result.stderr + result.stdout
    output = (result.stdout + result.stderr).lower()
    for key in (DEALER, CUSTOMER):
        assert key.hex() not in output
        assert base64.b64encode(key).decode().lower() not in output
        assert ", ".join(str(byte) for byte in key) not in output
        assert ", ".join(f"0x{byte:02x}" for byte in key) not in output


@pytest.mark.parametrize(
    ("payload", "status"),
    [
        (archive("classes.dex", b"dex\n035\0"), "unsupported"),
        (b"not a ZIP archive", "error"),
        (archive("assemblies/assemblies.arm64_v8a.blob", b"XABA\x01"), "error"),
        (archive("assemblies/SyntheticFixture.dll", b"MZmalformed"), "error"),
    ],
)
def test_scan_is_incomplete_when_input_cannot_be_analyzed(
    tmp_path: Path,
    payload: bytes,
    status: Literal["unsupported", "error"],
) -> None:
    # Given: a corrupt container or an unsupported framework.
    path = tmp_path / "unsupported.apk"
    _ = path.write_bytes(payload)

    # When: the scanner attempts to inspect it.
    result = invoke(path)

    # Then: a successful clean scan is never claimed.
    assert result.returncode == 2, result.stderr + result.stdout
    report = Report.model_validate_json(result.stdout)
    assert report.findings == []
    assert any(item.status == status for item in report.coverage)
