"""Conservative findings from embedded constants and direct managed field reads."""

import hashlib
import re
import struct
from dataclasses import dataclass
from typing import Final

import dnfile
from dncil.cil.error import MethodBodyFormatError
from pefile import PEFormatError

from mavs_keys.clr import KeyField, ManagedImage, candidate_fields, methods
from mavs_keys.constants import Constant, initialized_constants
from mavs_keys.models import Assembly, Finding, ScanError, UnsupportedFormat

AUTH_CONTEXT: Final = re.compile(
    r"auth|crypt|cipher|hash|hmac|sign|credential|challenge", re.IGNORECASE
)


@dataclass(frozen=True, slots=True)
class ManagedEvidence:
    """Compact field evidence retained after each decoded method has been discarded."""

    constants: dict[int, Constant]
    usages: dict[int, set[str]]


def collect_evidence(image: ManagedImage, fields: tuple[KeyField, ...]) -> ManagedEvidence:
    """Accumulate credential facts without keeping an assembly's entire decoded IL."""
    constants: dict[int, Constant] = {}
    candidates = {key.token for key in fields}
    for body in methods(image, initializers=True):
        for item in initialized_constants(image, body):
            if item.field_token in candidates:
                constants[item.field_token] = item
    usages: dict[int, set[str]] = {token: set() for token in constants}
    if not constants:
        return ManagedEvidence(constants, usages)
    for body in methods(image, initializers=False):
        for instruction in body.instructions:
            if instruction.op == "ldsfld" and instruction.token in usages:
                usages[instruction.token].add(body.name)
    return ManagedEvidence(constants, usages)


def inspect_assembly(assembly: Assembly) -> tuple[Finding, ...]:
    """Confirm constant presence and direct uses, without claiming remote exploitability."""
    try:
        with dnfile.dnPE(data=assembly.data, clr_lazy_load=True) as pe:
            if not pe.net or not pe.net.mdtables or not pe.net.mdtables.TypeDef:
                raise UnsupportedFormat("No supported managed metadata in DLL")
            image = ManagedImage.parse(pe)
            fields = candidate_fields(image)
            if not fields:
                return ()
            evidence = collect_evidence(image, fields)
            findings: list[Finding] = []
            for key in fields:
                constant = evidence.constants.get(key.token)
                if constant is None:
                    continue
                uses = tuple(sorted(evidence.usages[key.token]))
                if not uses:
                    continue
                confidence = "high" if any(AUTH_CONTEXT.search(name) for name in uses) else "medium"
                findings.append(
                    Finding(
                        source=assembly.source,
                        type_name=key.type_name,
                        field_name=key.name,
                        byte_length=len(constant.value),
                        fingerprint=hashlib.sha256(constant.value).hexdigest(),
                        used_by=uses,
                        confidence=confidence,
                        severity=confidence,
                        evidence="Literal initializer and field reads; review shared-key use.",
                    )
                )
            return tuple(findings)
    except (PEFormatError, MethodBodyFormatError, UnicodeError, struct.error, IndexError) as error:
        raise ScanError(f"Invalid managed metadata ({type(error).__name__})") from error
