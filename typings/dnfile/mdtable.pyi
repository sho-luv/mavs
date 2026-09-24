from .base import MDTableIndex, MDTableRow

class HeapItemString: ...

class ClrFieldAttr:
    fdStatic: bool  # noqa: N815

class FieldRow(MDTableRow):
    Name: HeapItemString
    Flags: ClrFieldAttr

class MethodDefRow(MDTableRow):
    Name: HeapItemString
    Rva: int

class TypeDefRow(MDTableRow):
    TypeName: HeapItemString
    TypeNamespace: HeapItemString
    FieldList: list[MDTableIndex[FieldRow]]
    MethodList: list[MDTableIndex[MethodDefRow]]

class TypeRefRow(MDTableRow):
    TypeName: HeapItemString
    TypeNamespace: HeapItemString

class MemberRefRow(MDTableRow):
    Name: HeapItemString
    Class: MDTableIndex[MDTableRow]

class FieldRvaRow(MDTableRow):
    Field: MDTableIndex[FieldRow]
    Rva: int
