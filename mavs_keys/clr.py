"""Narrow dnfile/dncil metadata into typed, unexecuted IL evidence."""

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Final

import dnfile
from dncil.cil.body import CilMethodBody
from dncil.cil.body.reader import CilMethodBodyReaderBytes
from dncil.clr.token import StringToken, Token
from dnfile.base import MDTableRow
from dnfile.mdtable import MemberRefRow, MethodDefRow, TypeDefRow, TypeRefRow
from dnfile.stream import MetaDataTables, UserStringHeap

from mavs_keys.models import ScanError

FIELD_TABLE: Final = 0x04000000
MAX_METHOD_BYTES: Final = 1024 * 1024
SECRET_WORDS: Final = frozenset({"key", "secret", "password", "passwd", "credential", "token"})


@dataclass(frozen=True, slots=True)
class ManagedImage:
    """Required metadata validated once before traversing untrusted PE structures."""

    pe: dnfile.dnPE
    tables: MetaDataTables
    types: tuple[TypeDefRow, ...]
    strings: UserStringHeap | None

    @classmethod
    def parse(cls, pe: dnfile.dnPE) -> "ManagedImage":
        """Reject missing tables before constructing a traversable managed image."""
        net = pe.net
        if net is None or net.mdtables is None or net.mdtables.TypeDef is None:
            raise ScanError("No supported managed metadata in DLL")
        return cls(pe, net.mdtables, tuple(net.mdtables.TypeDef.rows), net.user_strings)

    def get_data(self, rva: int, length: int) -> bytes:
        """Normalize either PE backing-buffer representation to immutable bytes."""
        return bytes(self.pe.get_data(rva, length))


def secret_name(name: str) -> bool:
    """Select credential identifiers, excluding public-key metadata and lookup keys."""
    words = set(re.sub(r"([a-z])([A-Z])", r"\1_\2", name).lower().strip("_").split("_"))
    return bool(words & SECRET_WORDS) and not words & {
        "public",
        "dictionary",
        "lookup",
        "diversifier",
    }


@dataclass(frozen=True, slots=True)
class Instruction:
    """Operands remain internal; byte values never become report evidence."""

    op: str
    token: int = 0
    number: int | None = None
    text: bytes | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class Method:
    """One method body, retained only while extracting constant and usage evidence."""

    name: str
    instructions: tuple[Instruction, ...]


@dataclass(frozen=True, slots=True)
class KeyField:
    """A named credential candidate linked to its owning type and metadata token."""

    token: int
    name: str
    type_name: str


def row_at(pe: ManagedImage, token: int) -> MDTableRow | None:
    """Resolve a metadata token only when its table and row are in bounds."""
    table = pe.tables.tables.get(token >> 24)
    rid = token & 0xFFFFFF
    if table is None or not 0 < rid <= len(table.rows):
        return None
    return table.rows[rid - 1]


def type_name(row: TypeDefRow | TypeRefRow) -> str:
    """Construct the qualified CLR name used in exact metadata checks."""
    return f"{row.TypeNamespace}.{row.TypeName}".strip(".")


def is_byte_type(pe: ManagedImage, token: int) -> bool:
    """Require System.Byte before treating an array's RVA data as key bytes."""
    row = row_at(pe, token)
    return isinstance(row, (TypeDefRow, TypeRefRow)) and type_name(row) == "System.Byte"


def is_array_initializer(pe: ManagedImage, token: int) -> bool:
    """Require the runtime initializer, not merely a similarly named method."""
    row = row_at(pe, token)
    if not isinstance(row, MemberRefRow) or str(row.Name) != "InitializeArray":
        return False
    owner = row.Class.row
    return isinstance(owner, (TypeRefRow, TypeDefRow)) and type_name(owner) == (
        "System.Runtime.CompilerServices.RuntimeHelpers"
    )


def read_method(pe: ManagedImage, method: MethodDefRow) -> tuple[Instruction, ...]:
    """Read a bounded method body without loading or executing the assembly."""
    if not method.Rva:
        return ()
    raw = pe.get_data(method.Rva, MAX_METHOD_BYTES)
    body = CilMethodBody(CilMethodBodyReaderBytes(raw))
    result: list[Instruction] = []
    for instruction in body.instructions:
        op = instruction.opcode.name
        operand = instruction.operand
        token = operand.value if isinstance(operand, Token) else 0
        number = operand if isinstance(operand, int) else None
        text: bytes | None = None
        if isinstance(operand, StringToken) and pe.strings and str(method.Name) == ".cctor":
            value = pe.strings.get(operand.rid, errors="surrogatepass")
            if value is None or value.value is None:
                raise ScanError("Invalid managed user-string reference")
            text = value.value.encode("utf-8", errors="surrogatepass")
        if op.startswith("ldc.i4.") and op[-1:].isdigit():
            number = int(op[-1])
        result.append(Instruction(op, token, number, text))
    return tuple(result)


def candidate_fields(pe: ManagedImage) -> tuple[KeyField, ...]:
    """Select static credential fields with valid metadata references."""
    result: list[KeyField] = []
    for owner in pe.types:
        for reference in owner.FieldList:
            row = reference.row
            if row is None:
                raise ScanError("Invalid managed field reference")
            if row.Flags.fdStatic and secret_name(str(row.Name)):
                result.append(
                    KeyField(FIELD_TABLE | reference.row_index, str(row.Name), type_name(owner))
                )
    return tuple(result)


def methods(pe: ManagedImage, *, initializers: bool) -> Iterator[Method]:
    """Filter metadata before decoding static initializers or ordinary method bodies."""
    for owner in pe.types:
        for reference in owner.MethodList:
            row = reference.row
            if row is None:
                raise ScanError("Invalid managed method reference")
            if (str(row.Name) == ".cctor") != initializers:
                continue
            yield Method(f"{type_name(owner)}::{row.Name}", read_method(pe, row))
