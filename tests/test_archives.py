"""Archive format and resource-boundary regression cases."""

import io
import struct
import zipfile
from pathlib import Path

import lz4.block
import pytest

from mavs_keys.archives import load_assemblies
from mavs_keys.models import ScanError, UnsupportedFormat


def archive(entries: list[tuple[str, bytes]]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as output:
        for name, data in entries:
            output.writestr(name, data)
    return stream.getvalue()


def write_input(tmp_path: Path, payload: bytes) -> Path:
    path = tmp_path / "fixture.apk"
    _ = path.write_bytes(payload)
    return path


def test_loads_nested_compressed_assembly(tmp_path: Path) -> None:
    # Given a compressed Xamarin assembly inside an XAPK's base APK.
    assembly = b"MZ" + bytes(range(256))
    compressed = b"XALZ" + struct.pack("<II", 0, len(assembly))
    compressed += lz4.block.compress(assembly, store_size=False)
    apk = archive([("assemblies/Fixture.dll", compressed)])
    path = write_input(tmp_path, archive([("base.apk", apk)]))
    # When loading without filesystem extraction.
    result = load_assemblies(path)
    # Then bytes and their nested origin are retained.
    assert len(result) == 1
    assert result[0].data == assembly
    assert result[0].source.endswith("!base.apk!assemblies/Fixture.dll")


def test_loads_v1_store(tmp_path: Path) -> None:
    # Given one assembly stored after a v1 descriptor table.
    assembly = b"MZ synthetic managed payload"
    blob = b"XABA" + struct.pack("<IIII", 1, 1, 1, 3)
    blob += struct.pack("<IIIIII", 44, len(assembly), 0, 0, 0, 0)
    path = write_input(tmp_path, archive([("assemblies/assemblies.blob", blob + assembly)]))
    # When loading the store.
    result = load_assemblies(path)
    # Then the descriptor selects the assembly bytes.
    assert result[0].data == assembly
    assert result[0].source.endswith("!store_3_0.dll")


@pytest.mark.parametrize(
    "entries",
    [
        [("assemblies/a.dll", b"XALZ" + struct.pack("<II", 0, 2**31))],
        [("assemblies/assemblies.blob", b"XABA" + struct.pack("<IIII", 1, 4097, 1, 0))],
        [("assemblies/assemblies.blob", b"XABA" + struct.pack("<IIII", 1, 1, 1, 0))],
        [("assemblies/a.dll", b"XALZ")],
    ],
)
def test_rejects_corrupt_or_unbounded_payloads(
    tmp_path: Path,
    entries: list[tuple[str, bytes]],
) -> None:
    # Given malformed metadata or an oversized declared decompression allocation.
    path = write_input(tmp_path, archive(entries))
    # When loading, then a typed scan error stops parsing.
    with pytest.raises(ScanError):
        _ = load_assemblies(path)


@pytest.mark.parametrize(
    "entries",
    [
        [("classes.dex", b"dex")],
        [("lib/arm64-v8a/libassembly-store.so", b"ELF")],
        [("assemblies/assemblies.blob", b"XABA" + struct.pack("<IIII", 2, 0, 0, 0))],
        [("base.apk", archive([("another.apk", archive([]))]))],
    ],
)
def test_unsupported_is_not_clean(tmp_path: Path, entries: list[tuple[str, bytes]]) -> None:
    # Given a format outside the implemented managed-code coverage.
    path = write_input(tmp_path, archive(entries))
    # When loading, then unsupported coverage is explicit.
    with pytest.raises(UnsupportedFormat):
        _ = load_assemblies(path)


def test_duplicate_zip_names_are_rejected(tmp_path: Path) -> None:
    # Given ambiguous duplicate ZIP members.
    with pytest.warns(UserWarning, match="Duplicate name"):
        payload = archive([("a.dll", b"MZ first"), ("a.dll", b"MZ second")])
    path = write_input(tmp_path, payload)
    # When loading, then no ambiguous member is selected.
    with pytest.raises(ScanError, match="duplicate"):
        _ = load_assemblies(path)


@pytest.mark.parametrize("compression", [zipfile.ZIP_LZMA, zipfile.ZIP_BZIP2])
def test_malformed_compression_becomes_scan_error(tmp_path: Path, compression: int) -> None:
    # Given a valid ZIP directory pointing to malformed compressed assembly bytes.
    stream = io.BytesIO()
    member_name = "Fixture.dll"
    with zipfile.ZipFile(stream, "w", compression) as output:
        output.writestr(member_name, b"MZ" + bytes(range(256)))
    payload = bytearray(stream.getvalue())
    data_start = 30 + len(member_name)
    if compression == zipfile.ZIP_LZMA:
        payload[data_start + 4] = 0xFF
    else:
        payload[data_start] = 0xFF
    path = write_input(tmp_path, bytes(payload))
    # When loading, then the decoder failure remains inside the typed error boundary.
    with pytest.raises(ScanError):
        _ = load_assemblies(path)
