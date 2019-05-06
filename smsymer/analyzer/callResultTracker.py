from .tool import RefTracker
from smsymer.disassemble import Instruction


class CallResultTracker(RefTracker):
    def __init__(self, addr: int, height: int):
        super().__init__(addr, height)

    @property
    def is_buggy(self):
        return self.used is False

    def op(self, instruction: Instruction, stack_len: int):
        # cases that the result of call is actually checked
        if instruction.opcode == "JUMPI":
            self.use(instruction, stack_len)
        elif instruction.opcode == "RETURN":
            self.use(instruction, stack_len)
        else:
            self.pop(instruction.input_amount, stack_len)