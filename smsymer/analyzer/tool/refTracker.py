import copy
from typing import List

from smsymer.analyzer.exception import AnalyzerException
from smsymer.evm import Instruction, Stack


class RefTracker(object):
    # call invocation tracker
    def __init__(self, addr: int, height: int):
        self.addr: int = addr
        # one call result may have many duplications. height infers every reference (the bottom of stack is height 0)
        self.h_list: List[int] = [height]
        # if this call result is used by some operation
        self.used: bool = False
        self.use_addrs: List[int] = []

    def update(self, instruction: Instruction, stack: Stack):
        stack_len = len(stack)
        if instruction.opcode == "POP":
            self.pop(1, stack_len)
        elif 0x7f < instruction.bytecode < 0x7f + 17:
            # the instruction is DUP
            self.dup(stack_len - (instruction.bytecode - 0x7f), stack_len)
        elif 0x8f < instruction.bytecode < 0x8f + 17:
            # the instruction is SWAP
            self.swap(stack_len - (instruction.bytecode - 0x8f) - 1, stack_len)
        elif 0x0 < instruction.bytecode < 0x10:
            # arithmetic operation
            self.arith(instruction.input_amount, stack_len)
        elif 0x10 <= instruction.bytecode < 0x1a:
            # boolean operation
            self.boolean(instruction.input_amount, stack_len)
        elif instruction.opcode == "SHA3":
            self.sha3(stack_len)
        else:
            self.op(instruction, stack)

    def new(self, h):
        self.h_list.append(h)

    def dup(self, subject_h: int, stack_len: int):
        # check if there is any call result are duplicated
        if stack_len <= subject_h:
            raise AnalyzerException("CallInvocation.dup: stack_len <= source_h")
        if subject_h not in self.h_list:
            return
        else:
            self.h_list.append(stack_len)

    def pop(self, amount: int, stack_len: int):
        # check if any reference is popped out
        for i in range(amount):
            if stack_len - i - 1 in self.h_list:
                self.h_list.remove(stack_len - i - 1)

    def swap(self, subject_h: int, stack_len: int):
        # check if any reference is swapped
        if subject_h >= stack_len:
            raise AnalyzerException("CallInvocation.swap: stack_len <= source_h")
        if subject_h in self.h_list and stack_len - 1 not in self.h_list:
            self.h_list.remove(subject_h)
            self.h_list.append(stack_len - 1)
        elif subject_h not in self.h_list and stack_len - 1 in self.h_list:
            self.h_list.remove(stack_len - 1)
            self.h_list.append(subject_h)

    def arith(self, input_amount: int, stack_len: int):
        # check if the reference is used in an arithmetic operation, if so, the reference will be the arithmetic result
        if stack_len < input_amount:
            raise AnalyzerException("CallInvocation.arith: stack_len < amount")
        ll = copy.deepcopy(self.h_list)
        used = False
        for h in ll:
            if stack_len - input_amount <= h < stack_len:
                used = True
                self.h_list.remove(h)
        if used:
            self.h_list.append(stack_len - input_amount)

    def boolean(self, input_amount: int, stack_len: int):
        # check if the reference is used in a boolean operation, if so, the reference will be the operation result
        if stack_len < input_amount:
            raise AnalyzerException("CallInvocation.boolean: stack_len < amount")
        ll = copy.deepcopy(self.h_list)
        used = False
        for h in ll:
            if stack_len - input_amount <= h < stack_len:
                used = True
                self.h_list.remove(h)
        if used:
            self.h_list.append(stack_len - input_amount)

    def sha3(self, stack_len: int):
        # check if the reference is used in hash operation
        ll = copy.deepcopy(self.h_list)
        used = False
        for h in ll:
            if stack_len - 2 <= h < stack_len:
                used = True
                self.h_list.remove(h)
        if used:
            self.h_list.append(stack_len - 2)

    def use(self, ins: Instruction, stack_len: int):
        # check if any reference are used by some operation
        if stack_len < ins.input_amount:
            raise AnalyzerException("CallInvocation.use: stack_len < amount")
        ll = copy.deepcopy(self.h_list)
        for h in ll:
            if stack_len - ins.input_amount <= h < stack_len:
                self.h_list.remove(h)
                self.use_addrs.append(ins.addr)
                self.used = True

    @property
    def is_buggy(self):
        # need implementation, the logic of buggy
        return self.used

    def op(self, instruction: Instruction, stack: Stack):
        # need implementation, define how to deal with other operations
        # by default, it view every other operation as use of the reference
        self.use(instruction, len(stack))
