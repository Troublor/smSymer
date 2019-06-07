import copy
from typing import List

from z3 import simplify, Z3Exception, eq, z3

from smsymer import utils
from .immutableStorageTracker import ImmutableStorageTracker
from smsymer.evm import EVM, Instruction, PcPointer
from .tool import RefTracker
from .reentrancyTracker import ReentrancyTracker
from .callResultTracker import CallResultTracker
from .timestampDepTracker import TimestampDepTracker


class AnalysisVM(EVM):
    def __init__(self, pre_process=False):
        super().__init__(pre_process)
        self.pre_process = pre_process
        self.call_result_references: List[RefTracker] = []
        self.timestamp_references: List[RefTracker] = []
        self.reentrancy_references: List[ReentrancyTracker] = []
        self.immutable_storage_references: List[ImmutableStorageTracker] = []

    @property
    def trackers(self):
        return self.call_result_references + self.timestamp_references + self.reentrancy_references

    def _update_all_ref_tracker(self, instruction: Instruction):
        # update all the references
        for ref in self.call_result_references + self.timestamp_references + self.reentrancy_references:
            ref.update(instruction, self._stack, self.immutable_storage_references)
        # check if there are new references
        if instruction.opcode in ['CALL', "STATICCALL", "DELEGATECALL", "CALLCODE"]:
            h = len(self._stack) - instruction.input_amount
            if len(self.reentrancy_references) == 0:
                # 如果之前没有任何Storage被读取，也就是为创建任何ReentrancyTracker，那么当前的这个Call就是有reentrancy bug的
                tmp = ReentrancyTracker(instruction.addr, h, -1)
                tmp.buggy = True
                self.reentrancy_references.append(tmp)
            # 判断Call的目的地址是否是可变的（mutable）
            for ref in self.immutable_storage_references:
                if ref.contains(len(self._stack) - 2):
                    break
            else:
                # 当前的目的地址包含在某一个mutable storage reference中
                # 只有当目的地址不是一个确定值，也就是说不可靠的时候
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
            # 检查是否需要新建MutableStorageTracker
            if not utils.in_list(self.mutable_storage_addresses, storage_addr):
                # 是不可变的（immutable)
                for ref in self.immutable_storage_references:
                    if utils.eq(ref.storage_addr, storage_addr):
                        ref.new(h)
                        ref.new_born = True
                        break
                else:
                    ref = ImmutableStorageTracker(instruction.addr, h, storage_addr, self._storage[storage_addr])
                    self.immutable_storage_references.append(ref)
            # 检查是否需要新建ReentrancyTracker
            for r in self.reentrancy_references:
                # check if there already exists the same reference
                try:
                    if utils.is_symbol(storage_addr) and utils.is_symbol(r.storage_addr) and eq(
                            simplify(r.storage_addr), simplify(storage_addr)) or not utils.is_symbol(
                        storage_addr) and not utils.is_symbol(r.storage_addr) and r.storage_addr == storage_addr:
                        r.new(h)
                        break
                except Exception as e:
                    print(e)
            else:
                ref = ReentrancyTracker(instruction.addr, h, storage_addr)
                self.reentrancy_references.append(ref)

        # 更新mutable storage reference
        for ref in self.immutable_storage_references:
            if ref.new_born:
                ref.new_born = False
            else:
                ref.update(instruction, self._stack, None)

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

    def exe_with_path_condition(self, instruction: Instruction, path_condition: list = []) -> PcPointer:
        self._update_all_ref_tracker(instruction)
        if instruction.opcode == "SSTORE":
            # save the value of every referred storage variable before SSTORE
            bak = {}
            for ref in self.reentrancy_references:
                bak[ref] = self._storage[ref.storage_addr]
        if instruction.opcode == "SSTORE" and self.pre_process:
            op0 = self._stack[-1]
            # 在可信条件下进行修改的Storage变量仍然是可信的（immutable）
            caller = z3.Int("Is")
            solver = z3.Solver()
            solver.add(path_condition)
            if "sat" == str(solver.check()):
                for storage_addr, storage_value in self._storage.get_storage().items():
                    if not utils.in_list(self.mutable_storage_addresses, storage_addr):
                        # solver.add(caller & 0xffffffffffffffffffff != storage_value & 0xffffffffffffffffffff)
                        mask = 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff
                        if utils.is_symbol(storage_value):
                            # solver.add(z3.Int(str("Is") + "&" + str(mask)) != z3.Int(str(storage_value) + "&" + str(mask)))
                            # solver.add(z3.Int(str(mask) + "&" + str("Is")) != z3.Int(str(storage_value) + "&" + str(mask)))
                            # solver.add(z3.Int(str("Is") + "&" + str(mask)) != z3.Int(str(mask) + "&" + str(storage_value)))
                            # solver.add(z3.Int(str(mask) + "&" + str("Is")) != z3.Int(str(mask) + "&" + str(storage_value)))
                            # solver.add(z3.Int(str("Is")) != z3.Int(str(storage_value)))
                            solver.add(z3.Int(str("Is")) != z3.Int(str(storage_value)))
                        else:
                            # solver.add(z3.Int(str("Is") + "&" + str(mask)) != storage_value & mask)
                            # solver.add(z3.Int(str(mask) + "&" + str("Is")) != storage_value & mask)
                            solver.add(z3.Int(str("Is")) != storage_value & mask)
                if "sat" == str(solver.check()):
                    # caller不为任意一个可信storage变量的时候仍然可能进行SSTORE,则说明被修改的storage变量是不可靠的
                    if not utils.in_list(self.mutable_storage_addresses, op0):
                        self.mutable_storage_addresses.append(op0)
        pc_pointer = super().exe(instruction)
        if instruction.opcode == "SSTORE":
            # check if any referred storage variable is changed after SSTORE
            # if len(bak) != len(self._storage):
            #     # 如果新增了Storage变量，那么一定是做修改了
            #     ref.storage_changed = True
            #     if ref.after_used_in_condition:
            #         ref.changed_after_condition = True
            #     if not ref.after_call:
            #         ref.changed_before_call = True
            # else:
            # 如果Storage变量的个数没变，那么就检查每一个变量的值有没有改变
            for ref, value in bak.items():
                if utils.is_symbol(value) is not utils.is_symbol(self._storage[ref.storage_addr]) or \
                        utils.is_symbol(value) and not eq(simplify(value),
                                                          simplify(self._storage[ref.storage_addr])) or \
                        not utils.is_symbol(value) and value != self._storage[ref.storage_addr]:
                    ref.storage_changed = True
                    if ref.after_used_in_condition:
                        ref.changed_after_condition = True
                    if not ref.after_call:
                        ref.changed_before_call = True
        return pc_pointer
