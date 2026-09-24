"""Recognize literal managed static-field initialization with bounded IL patterns."""

from dataclasses import dataclass, field
from typing import Final

from mavs_keys.clr import (
    FIELD_TABLE,
    Instruction,
    ManagedImage,
    Method,
    is_array_initializer,
    is_byte_type,
)
from mavs_keys.models import ScanError

MIN_KEY_BYTES: Final = 8
MAX_KEY_BYTES: Final = 512
ARRAY_INITIALIZER_LENGTH: Final = 6


@dataclass(frozen=True, slots=True)
class Constant:
    """An embedded initializer value kept out of repr and report serialization."""

    field_token: int
    value: bytes = field(repr=False)


def array_value(pe: ManagedImage, window: tuple[Instruction, ...]) -> bytes | None:
    """Resolve compiler-emitted byte-array data only with exact initializer evidence."""
    if len(window) != ARRAY_INITIALIZER_LENGTH:
        return None
    size, allocation, duplicate, data_token, call, _ = window
    if not size.op.startswith("ldc.i4") or size.number is None:
        return None
    if not MIN_KEY_BYTES <= size.number <= MAX_KEY_BYTES:
        return None
    if (allocation.op, duplicate.op, data_token.op, call.op) != (
        "newarr",
        "dup",
        "ldtoken",
        "call",
    ):
        return None
    if not is_byte_type(pe, allocation.token) or not is_array_initializer(pe, call.token):
        return None
    table = pe.tables.FieldRva
    if table is None:
        raise ScanError("Managed array initializer has no RVA data table")
    for row in table.rows:
        if FIELD_TABLE | row.Field.row_index == data_token.token:
            value = pe.get_data(row.Rva, size.number)
            if len(value) != size.number:
                raise ScanError("Truncated managed array constant")
            return value
    raise ScanError("Managed array initializer refers to missing RVA data")


def initialized_constants(pe: ManagedImage, method: Method) -> tuple[Constant, ...]:
    """Detect direct strings and byte arrays; computed and dynamic values are excluded."""
    if not method.name.endswith("::.cctor"):
        return ()
    instructions = tuple(item for item in method.instructions if item.op != "nop")
    result: list[Constant] = []
    for index, item in enumerate(instructions):
        if item.op != "stsfld" or index == 0:
            continue
        previous = instructions[index - 1]
        value = previous.text if previous.op == "ldstr" else None
        if value is None and index >= ARRAY_INITIALIZER_LENGTH - 1:
            value = array_value(pe, instructions[index - ARRAY_INITIALIZER_LENGTH + 1 : index + 1])
        if value is not None and MIN_KEY_BYTES <= len(value) <= MAX_KEY_BYTES:
            result.append(Constant(item.token, value))
    return tuple(result)
