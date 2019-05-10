from smsymer.analyzer.tool import RefTracker
from smsymer.evm import Instruction, Stack


class TimestampDepTracker(RefTracker):
    def __init__(self, addr: int, height: int):
        super().__init__(addr, height)

    @property
    def is_buggy(self):
        return self.used is True

    @property
    def root_cause_addr(self):
        return self.addr

    def op(self, instruction: Instruction, stack: Stack):
        # cases that the timestamp is used in conditional jump
        if instruction.opcode == "JUMPI":
            self.use(instruction, len(stack))
        else:
            self.pop(instruction.input_amount, len(stack))
