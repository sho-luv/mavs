"""Read bounded managed payloads without executing code or extracting paths."""

import io
import lzma
import zipfile
import zlib
from pathlib import Path, PurePosixPath
from typing import Final

import lz4.block

from mavs_keys.models import Assembly, ScanError, UnsupportedFormat

MAX_INPUT: Final = 256 * 1024 * 1024
MAX_MEMBER: Final = 128 * 1024 * 1024
MAX_TOTAL: Final = 512 * 1024 * 1024
MAX_ENTRIES: Final = 4096
STORE_HEADER: Final = 20
STORE_RECORD: Final = 24
COMPRESSED_HEADER: Final = 12


class _Budget:
    """Accumulate allocations and entry counts across nested archive boundaries."""

    __slots__: tuple[str, ...] = ("entries", "total")

    def __init__(self) -> None:
        self.total: int = 0
        self.entries: int = 0

    def reserve(self, size: int, count: int = 0) -> None:
        if size > MAX_MEMBER or size < 0:
            raise ScanError("member exceeds the supported allocation limit")
        self.total += size
        self.entries += count
        if self.total > MAX_TOTAL or self.entries > MAX_ENTRIES:
            raise ScanError("archive exceeds aggregate size or entry limits")


def _uint(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise ScanError("truncated integer in managed assembly header")
    return int.from_bytes(data[offset : offset + 4], "little")


def _decompress(assembly: Assembly, budget: _Budget) -> Assembly:
    if not assembly.data.startswith(b"XALZ"):
        return assembly
    size = _uint(assembly.data, 8)
    if size == 0:
        raise ScanError("empty Xamarin compressed assembly")
    budget.reserve(size)
    try:
        data = lz4.block.decompress(
            assembly.data[COMPRESSED_HEADER:],
            uncompressed_size=size,
        )
    except lz4.block.LZ4BlockError as error:
        raise ScanError("invalid Xamarin LZ4 payload") from error
    if len(data) != size:
        raise ScanError("Xamarin decompressed size differs from header")
    return Assembly(source=assembly.source, data=data)


def _store(assembly: Assembly, budget: _Budget) -> tuple[Assembly, ...]:
    data = assembly.data
    if len(data) < STORE_HEADER or not data.startswith(b"XABA"):
        raise ScanError("invalid Xamarin assembly-store header")
    version = _uint(data, 4)
    if version != 1:
        raise UnsupportedFormat(f"Xamarin assembly-store version {version} is unsupported")
    local_count = _uint(data, 8)
    global_count = _uint(data, 12)
    store_id = _uint(data, 16)
    if global_count > MAX_ENTRIES:
        raise ScanError("Xamarin global entry count exceeds limit")
    budget.reserve(0, local_count)
    table_end = STORE_HEADER + local_count * STORE_RECORD
    if table_end > len(data):
        raise ScanError("truncated Xamarin assembly descriptor table")
    result: list[Assembly] = []
    for index in range(local_count):
        record = STORE_HEADER + index * STORE_RECORD
        offset = _uint(data, record)
        size = _uint(data, record + 4)
        for pair in range(3):
            span_offset = _uint(data, record + pair * 8)
            span_size = _uint(data, record + pair * 8 + 4)
            if span_offset > len(data) or span_offset + span_size > len(data):
                raise ScanError("Xamarin descriptor range exceeds store bounds")
            if span_size and span_offset < table_end:
                raise ScanError("Xamarin descriptor overlaps its header or table")
        if size == 0:
            raise ScanError("empty Xamarin assembly descriptor")
        budget.reserve(size)
        candidate = Assembly(
            source=f"{assembly.source}!store_{store_id}_{index}.dll",
            data=data[offset : offset + size],
        )
        result.append(_decompress(candidate, budget))
    return tuple(result)


def _members(archive: zipfile.ZipFile, budget: _Budget) -> list[zipfile.ZipInfo]:
    members = archive.infolist()
    names: set[str] = set()
    for member in members:
        if member.filename in names:
            raise ScanError("duplicate ZIP member name")
        names.add(member.filename)
        budget.reserve(member.file_size, 1)
        if member.flag_bits & 1:
            raise UnsupportedFormat("encrypted ZIP members are unsupported")
    return members


def _zip(assembly: Assembly, budget: _Budget, *, nested: bool = False) -> tuple[Assembly, ...]:
    result: list[Assembly] = []
    with zipfile.ZipFile(io.BytesIO(assembly.data)) as archive:
        for member in _members(archive, budget):
            name = PurePosixPath(member.filename).name.lower()
            if name.endswith(".so") and name.startswith(("libassembly-store", "libassemblies")):
                raise UnsupportedFormat("native MAUI assembly stores are unsupported")
            is_store = name.startswith("assemblies") and name.endswith(".blob")
            is_dll = name.endswith(".dll")
            is_apk = name.endswith(".apk")
            if not (is_dll or is_store or is_apk):
                continue
            if is_apk and nested:
                raise UnsupportedFormat("APK nesting deeper than one level is unsupported")
            with archive.open(member) as stream:
                data = stream.read(MAX_MEMBER + 1)
            if len(data) != member.file_size or len(data) > MAX_MEMBER:
                raise ScanError("ZIP member size differs from bounded declaration")
            candidate = Assembly(source=f"{assembly.source}!{member.filename}", data=data)
            if is_apk:
                result.extend(_zip(candidate, budget, nested=True))
            elif is_store:
                result.extend(_store(candidate, budget))
            else:
                result.append(_decompress(candidate, budget))
    return tuple(result)


def load_assemblies(path: Path) -> tuple[Assembly, ...]:
    """Load APK/XAPK managed payloads under shared size and entry limits.

    Unsupported layouts raise explicitly so callers cannot report a clean scan.
    """
    try:
        if path.stat().st_size > MAX_INPUT:
            raise ScanError("input exceeds the supported file-size limit")
        with path.open("rb") as stream:
            data = stream.read(MAX_INPUT + 1)
        if len(data) > MAX_INPUT:
            raise ScanError("input exceeds the supported file-size limit")
        assemblies = _zip(Assembly(source=path.name, data=data), _Budget())
    except (OSError, zipfile.BadZipFile, EOFError, zlib.error, lzma.LZMAError) as error:
        raise ScanError("cannot read input as a valid APK/XAPK archive") from error
    except NotImplementedError as error:
        raise UnsupportedFormat("ZIP compression method is unsupported") from error
    if not assemblies:
        raise UnsupportedFormat("no supported managed assemblies found in APK/XAPK")
    return assemblies
