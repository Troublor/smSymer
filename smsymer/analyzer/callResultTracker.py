from smsymer.evm import Stack
from .tool import RefTracker
from smsymer.evm import Instruction


class CallResultTracker(RefTracker):
    def __init__(self, addr: int, height: int):
        super().__init__(addr, height)

    @property
    def is_buggy(self):
        return self.used is False

    @property
    def root_cause_addr(self):
        return self.addr

    def op(self, instruction: Instruction, stack: Stack, *args):
        # cases that the result of call is actually checked
        if instruction.opcode == "JUMPI":
            self.use(instruction, len(stack))
        elif instruction.opcode == "RETURN":
            self.use(instruction, len(stack))
        else:
            self.pop(instruction.input_amount, len(stack))
