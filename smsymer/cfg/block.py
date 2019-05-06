from typing import List

from smsymer.evm import Instruction


class Block(object):
    """
    Node in Control Flow Graph
    """

    def __init__(self, instructions: List[Instruction]):
        self.instructions = instructions

    @property
    def address(self) -> int:
        return self.instructions[0].addr

    @property
    def lass_address(self) -> int:
        return self.instructions[-1].addr

    def __str__(self):
        return hex(self.address)

    def __getitem__(self, item):
        if type(item) is int:
            return self.instructions[item]
        else:
            raise AttributeError("Block instructions do not support slice")

    def __eq__(self, other):
        return self.address == other.address

    def __ne__(self, other):
        return self.address != other.address

    def __len__(self):
        return len(self.instructions)

    def contains_call(self) -> bool:
        for ins in self.instructions:
            if ins.opcode in ["CALL", "STATICCALL", "DELEGATECALL", "CALLCODE"]:
                return True
        else:
            return False