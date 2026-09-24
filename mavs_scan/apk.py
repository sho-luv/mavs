"""Bounded APK/XAPK loading built on apkInspector and the standard library.

Loading never executes package code. Archives are read in memory with entry and
size limits so a hostile package cannot exhaust resources during triage.
"""

from __future__ import annotations

import io
import struct
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

import defusedxml.ElementTree as DET
from apkInspector.axml import get_manifest

from mavs_scan.model import Coverage

ANDROID_NS: Final = "http://schemas.android.com/apk/res/android"
_MAX_ENTRIES: Final = 40_000
_MAX_MEMBER_BYTES: Final = 400 * 1024 * 1024
_SIG_BLOCK_MAGIC: Final = b"APK Sig Block 42"
_V2_ID: Final = 0x7109871A
_V3_ID: Final = 0xF05368C0


def android_attr(elem: ET.Element, name: str) -> str | None:
    """Return an android-namespaced attribute value, or ``None`` if absent."""
    return elem.get(f"{{{ANDROID_NS}}}{name}")


@dataclass(slots=True)
class LoadedApk:
    """An opened APK exposing manifest, entries and signing material.

    Attributes:
        path: Source path of the APK (the inner base APK for an XAPK).
        raw: Full APK bytes, retained for signing-block parsing.
        file_type: ``apk`` or ``xapk`` describing the original input.
        manifest_xml: Decoded ``AndroidManifest.xml`` text, if available.
        manifest_root: Parsed manifest element tree root, if decodable.
        coverage: Per-stage notes accumulated while loading.
    """

    path: str
    raw: bytes = field(repr=False)
    file_type: str
    manifest_xml: str | None = None
    manifest_root: ET.Element | None = None
    coverage: list[Coverage] = field(default_factory=list)

    @property
    def zip(self) -> zipfile.ZipFile:
        """Return a fresh :class:`zipfile.ZipFile` over the retained bytes."""
        return zipfile.ZipFile(io.BytesIO(self.raw))

    def names(self) -> list[str]:
        """Return archive member names, capped by the entry limit."""
        with self.zip as archive:
            return archive.namelist()[:_MAX_ENTRIES]

    def read(self, name: str) -> bytes | None:
        """Return one member's bytes, or ``None`` if missing or oversized."""
        try:
            with self.zip as archive:
                info = archive.getinfo(name)
                if info.file_size > _MAX_MEMBER_BYTES:
                    return None
                return archive.read(name)
        except (KeyError, zipfile.BadZipFile, OSError):
            return None

    def dex_blobs(self) -> list[tuple[str, bytes]]:
        """Return ``(name, bytes)`` for each top-level ``classes*.dex``."""
        out: list[tuple[str, bytes]] = []
        for name in self.names():
            if name.startswith("classes") and name.endswith(".dex") and "/" not in name:
                data = self.read(name)
                if data is not None:
                    out.append((name, data))
        return out

    def native_libs(self) -> list[str]:
        """Return archive paths of bundled native ``.so`` libraries."""
        return [n for n in self.names() if n.startswith("lib/") and n.endswith(".so")]

    def certificates(self) -> tuple[list[bytes], list[str]]:
        """Return ``(der_certs, schemes)`` from v1 and v2/v3 signing data."""
        return _extract_certificates(self.raw)


def _decode_manifest(
    raw_apk: bytes, coverage: list[Coverage]
) -> tuple[str | None, ET.Element | None]:
    try:
        with zipfile.ZipFile(io.BytesIO(raw_apk)) as archive:
            manifest_raw = archive.read("AndroidManifest.xml")
    except (KeyError, zipfile.BadZipFile, OSError) as exc:
        coverage.append(Coverage(stage="manifest", status="error", detail=f"unreadable: {exc}"))
        return None, None
    try:
        xml = get_manifest(io.BytesIO(manifest_raw))
    except (ValueError, struct.error, OSError, RuntimeError) as exc:
        coverage.append(Coverage(stage="manifest", status="error", detail=f"undecodable: {exc}"))
        return None, None
    try:
        root = DET.fromstring(xml)
    except ET.ParseError as exc:
        coverage.append(Coverage(stage="manifest", status="partial", detail=f"xml parse: {exc}"))
        return xml, None
    coverage.append(Coverage(stage="manifest", status="ok", detail="decoded AndroidManifest.xml"))
    return xml, root


def _base_apk_from_xapk(raw: bytes, coverage: list[Coverage]) -> bytes | None:
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            candidates = [
                n
                for n in archive.namelist()
                if n.endswith(".apk") and "config." not in n.rsplit("/", 1)[-1]
            ]
            candidates.sort(key=len)
            for name in candidates:
                info = archive.getinfo(name)
                if info.file_size <= _MAX_MEMBER_BYTES:
                    return archive.read(name)
    except (zipfile.BadZipFile, OSError) as exc:
        coverage.append(Coverage(stage="container", status="error", detail=f"xapk: {exc}"))
        return None
    coverage.append(Coverage(stage="container", status="unsupported", detail="no base apk in xapk"))
    return None


def load(path: Path) -> LoadedApk:
    """Load an APK or XAPK from ``path`` into an in-memory :class:`LoadedApk`."""
    coverage: list[Coverage] = []
    raw = path.read_bytes()
    file_type = "unknown"
    apk_bytes = raw
    lower = path.name.lower()
    if lower.endswith(".xapk") or (raw[:2] == b"PK" and _looks_like_xapk(raw)):
        file_type = "xapk"
        inner = _base_apk_from_xapk(raw, coverage)
        if inner is not None:
            apk_bytes = inner
            coverage.append(Coverage(stage="container", status="ok", detail="extracted base apk"))
    elif lower.endswith(".apk") or raw[:2] == b"PK":
        file_type = "apk"
    manifest_xml, manifest_root = _decode_manifest(apk_bytes, coverage)
    return LoadedApk(
        path=str(path),
        raw=apk_bytes,
        file_type=file_type,
        manifest_xml=manifest_xml,
        manifest_root=manifest_root,
        coverage=coverage,
    )


def _looks_like_xapk(raw: bytes) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            names = archive.namelist()
    except (zipfile.BadZipFile, OSError):
        return False
    has_manifest_json = any(n == "manifest.json" for n in names)
    has_inner_apk = any(n.endswith(".apk") for n in names)
    return has_manifest_json and has_inner_apk


def _extract_certificates(raw: bytes) -> tuple[list[bytes], list[str]]:
    certs: list[bytes] = []
    schemes: list[str] = []
    v1 = _extract_v1_certs(raw)
    if v1:
        schemes.append("v1")
        certs.extend(v1)
    block = _find_signing_block(raw)
    if block is not None:
        for scheme_id, name in ((_V2_ID, "v2"), (_V3_ID, "v3")):
            value = block.get(scheme_id)
            if value is None:
                continue
            schemes.append(name)
            der = _first_cert_from_v2v3(value)
            if der is not None:
                certs.append(der)
    return certs, schemes


def _extract_v1_certs(raw: bytes) -> list[bytes]:
    out: list[bytes] = []
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            sig_files = [
                n
                for n in archive.namelist()
                if n.upper().startswith("META-INF/")
                and n.upper().rsplit(".", 1)[-1] in {"RSA", "DSA", "EC"}
            ]
            for name in sig_files:
                der = _pkcs7_first_cert(archive.read(name))
                if der is not None:
                    out.append(der)
    except (zipfile.BadZipFile, OSError):
        return out
    return out


def _pkcs7_first_cert(pkcs7: bytes) -> bytes | None:
    try:
        from asn1crypto import cms  # noqa: PLC0415

        info = cms.ContentInfo.load(pkcs7)
        signed = info["content"]
        for cert in signed["certificates"]:
            return cert.chosen.dump()
    except (ValueError, KeyError, TypeError):
        return None
    return None


def _find_signing_block(raw: bytes) -> dict[int, bytes] | None:
    cd_offset = _central_dir_offset(raw)
    if cd_offset is None or cd_offset < 24:
        return None
    if raw[cd_offset - 16 : cd_offset] != _SIG_BLOCK_MAGIC:
        return None
    footer_size = struct.unpack_from("<Q", raw, cd_offset - 24)[0]
    block_start = cd_offset - 8 - footer_size
    if block_start < 0 or block_start + 8 > cd_offset:
        return None
    pairs: dict[int, bytes] = {}
    pos = block_start + 8
    end = cd_offset - 24
    while pos + 12 <= end:
        pair_len = struct.unpack_from("<Q", raw, pos)[0]
        if pair_len < 4 or pos + 8 + pair_len > cd_offset:
            break
        scheme_id = struct.unpack_from("<I", raw, pos + 8)[0]
        pairs[scheme_id] = raw[pos + 12 : pos + 8 + pair_len]
        pos += 8 + pair_len
    return pairs


def _central_dir_offset(raw: bytes) -> int | None:
    idx = raw.rfind(b"PK\x05\x06")
    if idx < 0 or idx + 20 > len(raw):
        return None
    return struct.unpack_from("<I", raw, idx + 16)[0]


def _read_len_prefixed(buf: bytes, pos: int) -> tuple[bytes, int] | None:
    if pos + 4 > len(buf):
        return None
    length = struct.unpack_from("<I", buf, pos)[0]
    start = pos + 4
    if start + length > len(buf):
        return None
    return buf[start : start + length], start + length


def _first_cert_from_v2v3(value: bytes) -> bytes | None:
    signers = _read_len_prefixed(value, 0)
    if signers is None:
        return None
    signer = _read_len_prefixed(signers[0], 0)
    if signer is None:
        return None
    signed_data = _read_len_prefixed(signer[0], 0)
    if signed_data is None:
        return None
    digests = _read_len_prefixed(signed_data[0], 0)
    if digests is None:
        return None
    certs_seq = _read_len_prefixed(signed_data[0], 4 + len(digests[0]))
    if certs_seq is None:
        return None
    first = _read_len_prefixed(certs_seq[0], 0)
    return first[0] if first is not None else None
