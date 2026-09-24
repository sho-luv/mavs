# External typing surface

These local stubs describe only the dependency members used by MAVS. They are
based on dnfile 0.18.0, dncil 1.0.2, and lz4 4.4 source and runtime contracts.
They do not replace runtime validation of malformed input. dnfile metadata and
row references remain optional, PE byte reads can return bytes or bytearray,
and dncil operands preserve their supported alternatives.

Recheck the declarations when upgrading these dependencies. Stub-only helper
classes describe returned metadata attributes and are never runtime imports.
