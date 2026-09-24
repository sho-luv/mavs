"""Bounded extraction of the DEX string pool for pattern-based code rules.

This reads only the string-identifier table, which holds every string constant,
type descriptor, class name and method name a DEX references. It does not build
a control-flow or call graph and never executes bytecode. Pattern rules run over
these strings the way the legacy pipeline ran ``zipgrep`` over decompiled code,
but without external tools.
"""

from __future__ import annotations

import struct
from typing import Final

_HEADER_MIN: Final = 112
_STRING_IDS_SIZE_OFF: Final = 56
_STRING_IDS_OFF_OFF: Final = 60
_MAX_STRINGS: Final = 800_000
_MAX_STRING_BYTES: Final = 8_192
_DEX_MAGIC: Final = b"dex\n"


def _read_uleb128(data: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if pos >= len(data) or shift > 28:
            return result, pos
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            break
        shift += 7
    return result, pos


def extract_strings(dex: bytes) -> list[str]:
    """Return decoded strings from one DEX blob's string-identifier table.

    Malformed offsets are skipped rather than raised so a truncated or hostile
    DEX still yields whatever strings parse cleanly.
    """
    if len(dex) < _HEADER_MIN or dex[:4] != _DEX_MAGIC:
        return []
    count = struct.unpack_from("<I", dex, _STRING_IDS_SIZE_OFF)[0]
    ids_off = struct.unpack_from("<I", dex, _STRING_IDS_OFF_OFF)[0]
    count = min(count, _MAX_STRINGS)
    if ids_off + count * 4 > len(dex):
        count = max(0, (len(dex) - ids_off) // 4)
    out: list[str] = []
    for i in range(count):
        try:
            data_off = struct.unpack_from("<I", dex, ids_off + i * 4)[0]
        except struct.error:
            break
        if data_off >= len(dex):
            continue
        _, pos = _read_uleb128(dex, data_off)
        end = dex.find(b"\x00", pos, pos + _MAX_STRING_BYTES)
        if end < 0:
            end = min(pos + _MAX_STRING_BYTES, len(dex))
        out.append(dex[pos:end].decode("utf-8", errors="replace"))
    return out


def extract_all_strings(blobs: list[tuple[str, bytes]]) -> list[str]:
    """Return the combined, de-duplicated string pool across DEX blobs."""
    seen: set[str] = set()
    for _name, blob in blobs:
        seen.update(extract_strings(blob))
    return list(seen)
