from .base import ClrMetaDataTable, MDTableRow
from .mdtable import FieldRvaRow, TypeDefRow

class MetaDataTables:
    tables: dict[str | int, ClrMetaDataTable[MDTableRow]]
    TypeDef: ClrMetaDataTable[TypeDefRow] | None
    FieldRva: ClrMetaDataTable[FieldRvaRow] | None

class UserString:
    value: str | None

class UserStringHeap:
    def get(
        self, index: int, encoding: str = "utf-16", errors: str = "strict"
    ) -> UserString | None: ...
