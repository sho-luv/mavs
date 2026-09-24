"""Native shared-library hardening checks and outdated-library detection.

A minimal ELF reader inspects program headers for stack-execution and RELRO
protections and scans for the stack-canary symbol. It never runs the code. The
outdated-library scan preserves the legacy libpng/sqlite version check.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass

from mavs_scan.context import ScanContext
from mavs_scan.model import Finding, Severity

_PT_GNU_STACK = 0x6474E551
_PT_GNU_RELRO = 0x6474E552
_PF_X = 0x1
_ET_EXEC = 2
_MAX_LIBS = 60
_LIBPNG_RE = re.compile(rb"libpng version [0-9][0-9.]{2,10}")


@dataclass(frozen=True, slots=True)
class ElfFacts:
    """Hardening facts derived from one ELF file."""

    is_elf: bool
    executable_stack: bool
    has_relro: bool
    has_canary: bool
    is_pie: bool


def _parse_elf(data: bytes) -> ElfFacts:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return ElfFacts(False, False, False, False, True)
    is64 = data[4] == 2
    little = data[5] == 1
    end = "<" if little else ">"
    e_type = struct.unpack_from(end + "H", data, 16)[0]
    if is64:
        e_phoff = struct.unpack_from(end + "Q", data, 32)[0]
        phentsize, phnum = struct.unpack_from(end + "HH", data, 54)
    else:
        e_phoff = struct.unpack_from(end + "I", data, 28)[0]
        phentsize, phnum = struct.unpack_from(end + "HH", data, 42)
    executable_stack = False
    has_relro = False
    for i in range(min(phnum, 128)):
        off = e_phoff + i * phentsize
        if off + phentsize > len(data):
            break
        p_type = struct.unpack_from(end + "I", data, off)[0]
        p_flags = struct.unpack_from(end + "I", data, off + (4 if is64 else 24))[0]
        if p_type == _PT_GNU_STACK and p_flags & _PF_X:
            executable_stack = True
        if p_type == _PT_GNU_RELRO:
            has_relro = True
    return ElfFacts(
        is_elf=True,
        executable_stack=executable_stack,
        has_relro=has_relro,
        has_canary=b"__stack_chk_fail" in data,
        is_pie=e_type != _ET_EXEC,
    )


def analyze(ctx: ScanContext) -> list[Finding]:
    """Return native-library hardening and outdated-library findings."""
    libs = ctx.apk.native_libs()[:_MAX_LIBS]
    findings: list[Finding] = []
    no_nx: list[str] = []
    no_relro: list[str] = []
    no_canary: list[str] = []
    no_pie: list[str] = []
    outdated: set[str] = set()
    for name in libs:
        data = ctx.apk.read(name)
        if data is None:
            continue
        facts = _parse_elf(data)
        if not facts.is_elf:
            continue
        if facts.executable_stack:
            no_nx.append(name)
        if not facts.has_relro:
            no_relro.append(name)
        if not facts.has_canary:
            no_canary.append(name)
        if not facts.is_pie:
            no_pie.append(name)
        outdated |= _outdated(data)
    findings.extend(_aggregate(no_nx, no_relro, no_canary, no_pie))
    findings.extend(_outdated_finding(outdated))
    ctx.note("binary", "ok", f"{len(libs)} native lib(s) inspected")
    return findings


def _outdated(data: bytes) -> set[str]:
    found: set[str] = set()
    for match in _LIBPNG_RE.findall(data[:4_000_000]):
        found.add(match.decode("ascii", "replace"))
    return found


def _aggregate(
    no_nx: list[str],
    no_relro: list[str],
    no_canary: list[str],
    no_pie: list[str],
) -> list[Finding]:
    out: list[Finding] = []
    specs = (
        (
            "MAVS-BIN-NX",
            "Executable stack (NX disabled)",
            Severity.MEDIUM,
            no_nx,
            "CWE-119",
            "Native libraries have an executable stack, easing memory-corruption exploitation.",
        ),
        (
            "MAVS-BIN-PIE",
            "Native code not position-independent",
            Severity.MEDIUM,
            no_pie,
            "CWE-119",
            "Non-PIE binaries load at a fixed address, weakening ASLR.",
        ),
        (
            "MAVS-BIN-RELRO",
            "No RELRO protection",
            Severity.LOW,
            no_relro,
            "CWE-119",
            "Libraries lack RELRO, leaving the GOT writable during exploitation.",
        ),
        (
            "MAVS-BIN-CANARY",
            "No stack canary",
            Severity.LOW,
            no_canary,
            "CWE-121",
            "Libraries were built without stack canaries, easing stack overflow exploitation.",
        ),
    )
    for rule_id, title, severity, libs, cwe, desc in specs:
        if not libs:
            continue
        out.append(
            Finding(
                rule_id=rule_id,
                category="binary",
                title=title,
                severity=severity,
                description=desc,
                evidence=tuple(libs[:_MAX_LIBS]),
                cwe=cwe,
                masvs="MASVS-CODE-4",
            ),
        )
    return out


def _outdated_finding(outdated: set[str]) -> list[Finding]:
    if not outdated:
        return []
    return [
        Finding(
            rule_id="MAVS-BIN-OUTDATED",
            category="binary",
            title="Outdated bundled library version banner",
            severity=Severity.LOW,
            description=(
                "A bundled library reports a version banner. Check the identified "
                "version against known CVEs for that component."
            ),
            evidence=tuple(sorted(outdated)),
            cwe="CWE-1104",
            masvs="MASVS-CODE-3",
            verify="Compare the reported version against the library's CVE history.",
        ),
    ]
