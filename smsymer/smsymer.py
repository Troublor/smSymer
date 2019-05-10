import copy
from typing import List

from smsymer.analyzer import TimestampDepTracker, CallResultTracker, AnalysisVM, ReentrancyTracker
from smsymer.cfg import CFG, Block
from smsymer.evm import Instruction


class SmSymer(object):


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

        # self.body_cfg.df_traverse_cfg(print_blocks_with_call, 0, [0], [], AnalysisVM.init_state())
        for ref in self.body_cfg.buggy_refs.values():
            if isinstance(ref, ReentrancyTracker) and ref.is_buggy:
                return True
        return False
