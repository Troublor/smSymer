import copy
from typing import List

from smsymer.analyzer import TimestampDepTracker, CallResultTracker, AnalysisVM, ReentrancyTracker
from smsymer.cfg import CFG, Block
from smsymer.evm import Instruction


class SmSymer(object):
    def __init__(self, instructions: List[Instruction]):
        self.instructions = instructions
        c_blocks, b_blocks = self._construct_blocks()
        self.construct_cfg = CFG(c_blocks)
        self.body_cfg = CFG(b_blocks)

    def _construct_blocks(self):
        construct_blocks = []
        body_blocks = []

        def _save_block(instructions, is_cons):
            if is_cons:
                construct_blocks.append(Block(instructions))
            else:
                body_blocks.append(Block(instructions))

        def _remove_addr_offset(instruction, is_cons, offset):
            i = copy.deepcopy(instruction)
            if not is_cons:
                i.addr -= offset
            return i

        is_construct = True
        addr_offset = 0
        ins_set: List[Instruction] = []
        for ins in self.instructions:
            ins = _remove_addr_offset(ins, is_construct, addr_offset)
            if ins.opcode == 'JUMP' or ins.opcode == "JUMPI":
                ins_set.append(ins)
                _save_block(ins_set, is_construct)
                ins_set = []
            elif ins.opcode == 'JUMPDEST':
                if len(ins_set) != 0:
                    _save_block(ins_set, is_construct)
                ins_set = [ins]
            elif ins.opcode == 'RETURN':
                ins_set.append(ins)
                _save_block(ins_set, is_construct)
                is_construct = False
                ins_set = []
            elif ins.opcode == "STOP":
                if len(ins_set) == 0:
                    continue
                else:
                    ins_set.append(ins)
                    _save_block(ins_set, is_construct)
                    ins_set = []
            else:
                if len(ins_set) == 0 and len(body_blocks) == 0 and not is_construct:
                    # this is the first instruction in body
                    addr_offset = ins.addr
                    ins = _remove_addr_offset(ins, is_construct, addr_offset)
                ins_set.append(ins)
        return construct_blocks, body_blocks

    @property
    def timestamp_dependency(self) -> bool:
        # for t in self.construct_cfg.transitions:
        #     if "IHs" in str(t.constrain):
        #         self.report.timestamp_dependency = True
        # for t in self.body_cfg.transitions:
        #     if "IHs" in str(t.constrain):
        #         self.report.timestamp_dependency = True
        # return self.report.timestamp_dependency
        for ref in self.body_cfg.buggy_refs.values():
            if isinstance(ref, TimestampDepTracker) and ref.is_buggy:
                return True
        return False

    @property
    def unchecked_call(self) -> bool:
        for ref in self.body_cfg.buggy_refs.values():
            if isinstance(ref, CallResultTracker) and ref.is_buggy:
                return True
        return False

    @property
    def reentrancy(self) -> bool:
        def print_blocks_with_call(block_seq: List[Block], exe_path: List[int], path_condition: List, entry_state):
            for block in block_seq:
                if block.contains_call():
                    break
            else:
                return
            print("----------------")
            print(exe_path)
            print(path_condition)
            print("=>")
            print(block_seq)
            print("----------------")

            # check reentrancy bug
            # identify storage variables that are used in path conditions

        self.body_cfg.df_traverse_cfg(print_blocks_with_call, 0, [0], [], AnalysisVM.init_state())
        for ref in self.body_cfg.buggy_refs.values():
            if isinstance(ref, ReentrancyTracker) and ref.is_buggy:
                return True
        return False
