import copy
from typing import List

from z3 import simplify, Z3Exception, eq

from smsymer import utils
from smsymer.evm import EVM, Instruction, PcPointer
from .tool import RefTracker
from .reentrancyTracker import ReentrancyTracker
from .callResultTracker import CallResultTracker
from .timestampDepTracker import TimestampDepTracker


class AnalysisVM(EVM):
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
            ref.update(instruction, self._stack)
        # check if there are new references
        if instruction.opcode in ['CALL', "STATICCALL", "DELEGATECALL", "CALLCODE"]:
            h = len(self._stack) - instruction.input_amount
            if len(self.reentrancy_references) == 0:
                tmp = ReentrancyTracker(instruction.addr, h, None)
                tmp.buggy = True
                self.reentrancy_references.append(tmp)
            # new call result reference is generated
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
                try:
                    if utils.is_symbol(value) is not utils.is_symbol(self._storage[ref.storage_addr]) or \
                            utils.is_symbol(value) and not eq(simplify(value),
                                                              simplify(self._storage[ref.storage_addr])) or \
                            not utils.is_symbol(value) and value != self._storage[ref.storage_addr]:
                        ref.storage_changed = True
                        if ref.after_used_in_condition:
                            ref.changed_after_condition = True
                        if not ref.after_call:
                            ref.changed_before_call = True
                except Z3Exception as e:
                    print(e)
        return pc_pointer
