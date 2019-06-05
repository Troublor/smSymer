from smsymer.analyzer.tool import RefTracker
from smsymer.evm import Instruction, Stack


class TimestampDepTracker(RefTracker):
    def __init__(self, addr: int, height: int):
        super().__init__(addr, height)
        self.dependency_addr = -1

    @property
    def is_buggy(self):
        return self.used is True

    @property
    def root_cause_addr(self):
        return self.addr

    def op(self, instruction: Instruction, stack: Stack, immutable_storage_references):
        # cases that the timestamp is used in conditional jump
        if instruction.opcode == "JUMPI":
            not_used_before = not self.used
            self.use(instruction, len(stack))
            if not_used_before and self.used:
                self.dependency_addr = instruction.addr
        else:
            self.pop(instruction.input_amount, len(stack))
