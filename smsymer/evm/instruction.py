from typing import Union, List

from smsymer.disassemble import get_param_amount
from smsymer.evm.exception import InvalidOperationException, InsufficientInputException
from smsymer.evm.fact import get_operation_name, opcodes, get_input_amount, get_output_amount


class Instruction(object):
    def __init__(self, addr: int = -1, bytecode: int = -1, opcode: str = "", params: List[str] = None):
        # address is not necessary in each case
        self.addr = addr
        # bytecode and opcode, only need one
        self.opcode = opcode
        self.bytecode = bytecode
        if self.opcode == "" and self.bytecode >= 0:
            self.opcode = get_operation_name(self.bytecode)
        elif self.opcode != "" and self.bytecode == -1:
            self.bytecode = self.get_operation_bytecode(self.opcode)
        if get_operation_name(self.bytecode) != self.opcode:
            raise InvalidOperationException(self.bytecode)
        if get_param_amount(self.bytecode) != 0 and params is None:
            raise InsufficientInputException(self.bytecode, 0, get_param_amount(self.bytecode))
        if params is None:
            params = []
        self.params = list(map(lambda s: s.rjust(2, '0'), params))

    @staticmethod
    def get_operation_bytecode(name: str) -> Union[int, None]:
        for bytecode, operation in opcodes.items():
            if operation[0] == name:
                return bytecode
        return None

    @property
    def input_amount(self) -> int:
        return get_input_amount(self.bytecode)

    @property
    def output_amount(self) -> int:
        return get_output_amount(self.bytecode)

    def __str__(self):
        if self.opcode is None:
            return "{0} {1}".format(hex(self.addr), "Invalid")
        elif len(self.params) > 0:
            return "{0} {1} {2}".format(hex(self.addr), self.opcode, "0x" + "".join(self.params))
        else:
            return "{0} {1}".format(hex(self.addr), self.opcode)
