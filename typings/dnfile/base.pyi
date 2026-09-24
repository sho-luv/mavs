class MDTableRow: ...

class MDTableIndex[T: MDTableRow]:
    row_index: int
    @property
    def row(self) -> T | None: ...

class ClrMetaDataTable[T: MDTableRow]:
    rows: list[T]
