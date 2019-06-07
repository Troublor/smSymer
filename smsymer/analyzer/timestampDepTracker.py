from typing import List

from z3 import z3

from smsymer import utils
from .immutableStorageTracker import ImmutableStorageTracker
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

    def op(self, instruction: Instruction, stack: Stack, immutable_storage_references: List[ImmutableStorageTracker]):
        # cases that the timestamp is used in conditional jump
        if instruction.opcode == "JUMPI":
            # 检查是否是时间戳与一个固定值进行比较
            if utils.is_symbol(stack[-2]):
                for z3_ref in utils.extract_z3_ref(stack[-2]):
                    if utils.is_z3_constant(z3_ref):
                        # 是一个z3表达式中的常量
                        continue
                    elif z3.eq(z3_ref, z3.Int("IHs")):
                        # 是时间戳
                        continue
                    else:
                        for ref in immutable_storage_references:
                            if ref.contains(len(stack) - 2) and utils.is_symbol(ref.storage_value) and utils.in_list(
                                    utils.extract_z3_ref(ref.storage_value), z3_ref):
                                break
                        else:
                            # 不是一个不可变Storage变量
                            break
                        # 是某一个不可变Storage变量
                        continue
                else:
                    # 参与比较的所有变量都是常量（除了时间戳本身）
                    self.pop(instruction.input_amount, len(stack))
                    return
            not_used_before = not self.used
            self.use(instruction, len(stack))
            if not_used_before and self.used:
                self.dependency_addr = instruction.addr
        else:
            self.pop(instruction.input_amount, len(stack))
