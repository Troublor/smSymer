from smsymer.analyzer.tool import RefTracker
from smsymer.evm import Instruction


class TimestampDepTracker(RefTracker):
    def __init__(self, addr: int, height: int):
        super().__init__(addr, height)

    @property
    def is_buggy(self):
        return self.used is True

    def op(self, instruction: Instruction, stack_len: int):
        # cases that the timestamp is used in conditional jump
        if instruction.opcode == "JUMPI":
            self.use(instruction, stack_len)
        else:
            self.pop(instruction.input_amount, stack_len)
