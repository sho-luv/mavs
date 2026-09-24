from types import TracebackType
from typing import Self

from .stream import MetaDataTables, UserStringHeap

class ClrData:
    mdtables: MetaDataTables | None
    user_strings: UserStringHeap | None

class dnPE:  # noqa: N801
    net: ClrData | None
    def __init__(self, *, data: bytes, clr_lazy_load: bool = False) -> None: ...
    def __enter__(self) -> Self: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None: ...
    def get_data(self, rva: int = 0, length: int | None = None) -> bytes | bytearray: ...
