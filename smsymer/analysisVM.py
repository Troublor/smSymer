import copy
from typing import List

from z3 import eq, simplify, Z3Exception

from smsymer import utils
from smsymer.disassemble import Instruction
from smsymer.executor import VM, PcPointer


class AnalyzerException(object):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


class RefTracker(object):
    # call invocation tracker
    def __init__(self, addr: int, height: int):
        self.addr: int = addr
        # one call result may have many duplications. height infers every reference (the bottom of stack is height 0)
        self.h_list: List[int] = [height]
        # if this call result is used by some operation
        self.used: bool = False
        self.use_addrs: List[int] = []

    def update(self, instruction: Instruction, stack_len: int):
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
            self.op(instruction, stack_len)

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

    def op(self, instruction: Instruction, stack_len: int):
        # need implementation, define how to deal with other operations
        # by default, it view every other operation as use of the reference
        self.use(instruction, stack_len)


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


class ReentrancyTracker(RefTracker):
    # track the storage variable and see if it is used in the path condition of a CALL operation.
    def __init__(self, addr: int, height: int, storage_addr):
        super().__init__(addr, height)
        self.storage_addr = storage_addr
        self.contains_call = False
        self.storage_changed = False
        self.sstore_before_call = False

    def __eq__(self, other):
        return self.storage_addr == other.storage_addr

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.addr)

    @property
    def is_buggy(self):
        return self.used and self.contains_call and (not self.sstore_before_call or not self.storage_changed)

    def op(self, instruction: Instruction, stack_len: int):
        # cases that storage variables are used in the path condition of a CALL operation
        if instruction.opcode == "JUMPI":
            self.use(instruction, stack_len)
        elif instruction.opcode in ["CALL", "STATICCALL", "DELEGATECALL", "CALLCODE"]:
            self.contains_call = True
        else:
            self.pop(instruction.input_amount, stack_len)


class AnalysisVM(VM):
    def __init__(self):
        super().__init__()
        self.call_result_references: List[RefTracker] = []
        self.timestamp_references: List[RefTracker] = []
        self.reentrancy_references: List[ReentrancyTracker] = []

    @property
    def trackers(self):
        return self.call_result_references + self.timestamp_references + self.reentrancy_references

    def _update_all_ref_tracker(self, instruction: Instruction):
        # update all the references
        for ref in self.call_result_references + self.timestamp_references + self.reentrancy_references:
            ref.update(instruction, len(self._stack))
        # check if there are new references
        if instruction.opcode in ['CALL', "STATICCALL", "DELEGATECALL", "CALLCODE"]:
            gas = self._stack[-1]
            # check the gas forwarded
            if not utils.is_symbol(gas) and (int(gas) == 0 or int(gas) == 2300):
                return
            if '2300' in str(gas):
                return
                # new call result reference is generated
            h = len(self._stack) - instruction.input_amount
            call_ref = CallResultTracker(instruction.addr, h)
            self.call_result_references.append(call_ref)
        elif instruction.opcode == "TIMESTAMP":
            # new timestamp reference is generated here
            ref = TimestampDepTracker(instruction.addr, len(self._stack))
            self.timestamp_references.append(ref)
        elif instruction.opcode == "SLOAD":
            storage_addr = self._stack[-1]
            h = len(self._stack) - instruction.input_amount
            for r in self.reentrancy_references:
                # check if there already exists the same reference
                try:
                    if utils.is_symbol(storage_addr) and utils.is_symbol(r.storage_addr) and eq(
                            simplify(r.storage_addr), simplify(storage_addr)) or not utils.is_symbol(
                        storage_addr) and not utils.is_symbol(r.storage_addr) and r.storage_addr == storage_addr:
                        r.new(h)
                        return
                except Z3Exception:
                    print('z3 exception')
            ref = ReentrancyTracker(instruction.addr, h, storage_addr)
            self.reentrancy_references.append(ref)

    @classmethod
    def init_state(cls) -> list:
        return super().init_state() + [
            [],
            [],
        ]

    def backup(self):
        return super().backup() + [
            copy.deepcopy(self.call_result_references),
            copy.deepcopy(self.timestamp_references),
        ]

    def retrieve(self, bak):
        super().retrieve(bak[:3])
        self.call_result_references = bak[3]
        self.timestamp_references = bak[4]

    def reset(self):
        super().reset()
        self.call_result_references = []
        self.timestamp_references = []

    def exe(self, instruction: Instruction) -> PcPointer:
        self._update_all_ref_tracker(instruction)
        if instruction.opcode == "SSTORE":
            # save the value of every referred storage variable before SSTORE
            bak = {}
            for ref in self.reentrancy_references:
                bak[ref] = self._storage[ref.storage_addr]
        pc_pointer = super().exe(instruction)
        if instruction.opcode == "SSTORE":
            # check if any referred storage variable is changed after SSTORE
            for ref, value in bak.items():
                if utils.is_symbol(value) and not eq(simplify(value), simplify(self._storage[ref.storage_addr])) or \
                        not utils.is_symbol(value) and value != self._storage[ref.storage_addr]:
                    ref.storage_changed = True
                    if ref.contains_call is False:
                        ref.sstore_before_call = True
        return pc_pointer
