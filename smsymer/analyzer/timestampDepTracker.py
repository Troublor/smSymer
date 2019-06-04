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

    def op(self, instruction: Instruction, stack: Stack, *args):
        # cases that the timestamp is used in conditional jump
        if instruction.opcode == "JUMPI":
            # 如果参与运算的没有可变Storage，那么说明不存在timestamp dependency
            mutable_references = args[0]
            for ref in mutable_references:
                if ref.contains(len(stack) - 2):
                    break
            else:
                return
            not_used_before = not self.used
            self.use(instruction, len(stack))
            if not_used_before and self.used:
                self.dependency_addr = instruction.addr
        else:
            self.pop(instruction.input_amount, len(stack))
