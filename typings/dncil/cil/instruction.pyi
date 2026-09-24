from dncil.cil.opcode import OpCode
from dncil.clr.argument import Argument
from dncil.clr.local import Local
from dncil.clr.token import Token

class Instruction:
    opcode: OpCode
    operand: Token | Local | Argument | list[int] | int | float | None
