import copy
from functools import reduce
from typing import List, Dict

from z3 import Not, simplify

from smsymer import Printer, utils
from smsymer.analyzer import AnalysisVM, TimestampDepTracker, CallResultTracker, ReentrancyTracker
from smsymer.analyzer.exception import AnalyzerException
from smsymer.analyzer.tool import RefTracker
from smsymer.evm import PcPointer, Storage
from .block import Block
from .transition import Transition


class CFG(object):
    """
    Control Flow Graph
    """

    def __init__(self, blocks: List[Block], printer: Printer, verbose=False, world_state=None):
        self.printer = printer
        self.verbose = verbose
        self.blocks = blocks

        self.transitions: List[Transition] = []
        self._construct_state = []
        if verbose:
            printer.info("Initialized Analysis Virtual Machine")
        self.buggy_refs: Dict[int, RefTracker] = {}

        # the world and machine state when branch start. key is the last_address of branch block
        self.branch_entry_state: Dict[int, List] = {}

        self.block_dict: Dict[int: Block] = {}
        for block in self.blocks:
            self.block_dict[block.address] = block
        if verbose:
            printer.info("Start symbolic execution")

        mutable_addresses = []

        if world_state is not None:
            # 先前world state的情况，进行预处理
            self.vm = AnalysisVM(pre_process=True)
            self.vm.retrieve_world_state(world_state)
            self._build_transitions()
            mutable_addresses = self.vm.mutable_storage_addresses
            self.transitions = []
            self._construct_state = []
            self.buggy_refs = {}
            self.branch_entry_state = {}
            self.block_dict = {}
        self.vm = AnalysisVM(pre_process=False)
        if world_state is not None:
            self.vm.retrieve_world_state(world_state)
        self.vm.mutable_storage_addresses = mutable_addresses
        self._build_transitions()

        if verbose:
            printer.info("Symbolic execution completed")
            n = 0
            for transition in self.transitions:
                if transition.constrain is True or transition.constrain is False:
                    n += 1
            printer.info("Number of actual conditional jump: {0}".format(n))

        # auxiliary variable for _df_traverse_cfg
        # including loop, every block can only be visited twice
        # dict(block_addr => visit_times)
        self.visited_block: Dict[int, int] = {}

    def df_traverse_cfg(self, func, start_addr: int, exe_path: List[int], path_condition: List, entry_state: List):
        """
        depth first traverse the cfg
        traverse unit is a sequence of block that do not have branch
        :param exe_path:
        :param entry_state: the world and machine state when enter this sequence
        :param func: the function (block_addr_seq:List[Block], exe_path, entry_path_condition, entry_state)
        which is used to process the block sequence.
        :param start_addr: block sequence first address
        :param path_condition: entry path condition
        """
        block_addr_seq = self._get_block_addr_sequence(start_addr)
        func(list(map(lambda a: self.block_dict[a], block_addr_seq)), exe_path, path_condition, entry_state)
        # increment the visit times of blocks in the block_addr_seq
        for addr in block_addr_seq:
            if addr in self.visited_block:
                self.visited_block[addr] += 1
            else:
                self.visited_block[addr] = 1
        transitions = self._find_transition(from_=self.block_dict[block_addr_seq[-1]])
        if len(transitions) == 0:
            return
        cond = copy.deepcopy(path_condition)
        path = copy.deepcopy(exe_path)
        for tran in transitions:
            cond.append(tran.constrain)
            path.append(tran.to_.address)
            if tran.to_.address not in self.visited_block or self.visited_block[tran.to_.address] < 2:
                # including loop, every block can only be visited twice
                try:
                    self.df_traverse_cfg(func, tran.to_.address, path, cond,
                                         self.branch_entry_state[tran.from_.lass_address])
                except KeyError as e:
                    print(e)
            path.pop(-1)
            cond.pop(-1)

    def _get_block_addr_sequence(self, start_addr: int) -> List[int]:
        # get the address sequence of blocks that execute sequentially
        seq = [start_addr]
        addr = start_addr
        transitions = self._find_transition(from_=self.block_dict[addr])
        while len(transitions) == 1:
            seq.append(transitions[0].to_.address)
            transitions = self._find_transition(from_=transitions[0].to_)
        return seq

    def _find_transition(self, from_: Block = None, to_: Block = None) -> List[Transition]:
        if from_ is None and to_ is None:
            raise AttributeError("Both from_ and to_ is None")
        r = []
        for trans in self.transitions:
            if from_ is not None and trans.from_ == from_ or to_ is not None and trans.to_ == to_:
                r.append(trans)
        return r

    def _get_block_index(self, addr: int) -> int:
        if utils.is_symbol(addr):
            raise AnalyzerException("Do not support symbolic JUMP destination")
        for index, block in enumerate(self.blocks):
            if block.address == addr:
                return index

    def _add_transition(self, block0: Block, block1: Block, constrain=True) -> bool:
        # return if this is a loop transition
        t = Transition(block0, block1, constrain)
        for trans in self.transitions:
            if trans.from_.address == block1.address or trans.from_.address == block0.address and trans.to_.address == block1.address:
                # loop transition
                self.transitions.append(t)
                return True
        self.transitions.append(t)
        return False

    def _build_transitions(self):
        recursion_depth = 0

        def _traverse_block_recursively(pc_b):
            nonlocal recursion_depth
            try:
                block = self.blocks[pc_b]
            except IndexError as e:
                print(e)
            # print("Traverse block {0}".format(block))
            pc_i = 0
            while True:
                ins = block[pc_i]
                # if ins.opcode is "CALL":
                #     print(ins)
                pc_pointer = self.vm.exe(ins)
                if pc_pointer.status == PcPointer.NEXT_ADDR:
                    if pc_i == len(block) - 1:
                        bak = self.vm.backup()
                        self.branch_entry_state[block.lass_address] = copy.deepcopy(bak)
                        _traverse_block_recursively(pc_b + 1)
                        break
                    else:
                        pc_i = pc_i + 1
                elif pc_pointer.status == PcPointer.STOP:
                    # print("END AT-" + str(block) + "-" + str(recursion_depth))
                    bak = self.vm.backup()
                    self.branch_entry_state[block.lass_address] = copy.deepcopy(bak)
                    break
                elif pc_pointer.status == PcPointer.JUMP:
                    last_block = self.blocks[pc_b]
                    bak = self.vm.backup()
                    self.branch_entry_state[last_block.lass_address] = copy.deepcopy(bak)
                    pc_bb = self._get_block_index(pc_pointer.addr)
                    # if pc_bb is None:
                    #     print(False)
                    if pc_bb is None:
                        print()
                    is_loop = self._add_transition(last_block, self.blocks[pc_bb])
                    if not is_loop:
                        _traverse_block_recursively(pc_bb)
                    # print("Jump to block: {0}".format(self.blocks[pc_bb]))
                    break
                elif pc_pointer.status == PcPointer.JUMPI:
                    recursion_depth += 1

                    last_block = self.blocks[pc_b]
                    # print("BRANCH-AT-" + str(last_block) + "-" + str(recursion_depth) + "-" + str(pc_pointer.condition))
                    bak = self.vm.backup()
                    self.branch_entry_state[last_block.lass_address] = copy.deepcopy(bak)

                    # suppose condition is true
                    pc_bb = self._get_block_index(pc_pointer.addr)
                    # if pc_bb is None:
                    #     print(False)
                    is_loop = self._add_transition(last_block, self.blocks[pc_bb], pc_pointer.condition)
                    if not is_loop:
                        # print("BRANCH-1: {0}".format(self.blocks[pc_bb]))
                        bak = self.vm.backup()
                        _traverse_block_recursively(pc_bb)
                        # save the buggy references before trace back
                        for tracker in self.vm.trackers:
                            if tracker.is_buggy and tracker.addr not in self.buggy_refs:
                                self.buggy_refs[tracker.addr] = tracker
                        self.vm.retrieve(bak)
                    # print("Back to block: {0}".format(last_block))
                    # suppose condition is false
                    pc_bb = pc_b + 1
                    is_loop = self._add_transition(last_block, self.blocks[pc_bb], Not(pc_pointer.condition))
                    if not is_loop:
                        # print("BRANCH-2: {0}".format(self.blocks[pc_bb]))
                        _traverse_block_recursively(pc_bb)
                    # print("END-BRANCH-" + str(recursion_depth))
                    recursion_depth -= 1
                    break

        _traverse_block_recursively(0)

    def exe_block_seq(self, block_seq: List[Block], stop_addr: int, init_state: List):
        bak = self.vm.backup()
        self.vm.retrieve(init_state)
        for ins in reduce(lambda l1, l2: l1 + l2, map(lambda block: block.instructions, block_seq)):
            self.vm.exe(ins)
            if ins.addr == stop_addr:
                break
        self.vm.retrieve(bak)

    @property
    def instructions(self):
        return reduce(lambda x, y: x + y, map(lambda b: b.instructions, self.blocks))

    def get_instruction(self, addr: int):
        for ins in self.instructions:
            if ins.addr == addr:
                return ins
        return addr

    def check_timestamp_dependency(self) -> dict:
        # for t in self.construct_cfg.transitions:
        #     if "IHs" in str(t.constrain):
        #         self.report.timestamp_dependency = True
        # for t in self.body_cfg.transitions:
        #     if "IHs" in str(t.constrain):
        #         self.report.timestamp_dependency = True
        # return self.report.timestamp_dependency
        r = {
            "vulnerable": False,
            "spots": []
        }
        for ref in self.buggy_refs.values():
            if isinstance(ref, TimestampDepTracker) and ref.is_buggy:
                r["vulnerable"] = True
                report = {
                    "timestamp_address": ref.root_cause_addr,
                    "dependency_address": ref.dependency_addr
                }
                r["spots"].append(report)
        return r

    def check_unchecked_call(self) -> dict:
        r = {
            "vulnerable": False,
            "spots": []
        }
        for ref in self.buggy_refs.values():
            if isinstance(ref, CallResultTracker) and ref.is_buggy:
                r["vulnerable"] = True
                report = {
                    "call_address": ref.root_cause_addr,
                }
                r["spots"].append(report)
        return r

    def check_reentrancy(self) -> dict:
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
        r = {
            "vulnerable": False,
            "spots": []
        }
        for ref in self.buggy_refs.values():
            if isinstance(ref, ReentrancyTracker) and ref.is_buggy:
                r["vulnerable"] = True

                for addr in ref.vulnerable_calls:
                    for index, report in enumerate(r["spots"].copy()):
                        if addr is None:
                            print(1)
                        if report["call_address"] is None:
                            print(2)
                        if addr == report["call_address"] and not utils.in_list(report["storage_addresses"],
                                                                                ref.storage_addr):
                            r["spots"][index]["storage_addresses"].append(ref.storage_addr)
                            break
                    else:
                        report = {
                            "call_address": addr,
                            "storage_addresses": [ref.storage_addr],
                        }
                        r["spots"].append(report)

        # check calls without associated storage variable
        for rr in self.check_unchecked_call()["spots"]:
            for ref in self.vm.reentrancy_references:
                if utils.in_list(ref.checked_calls, rr["call_address"]):
                    break
            else:
                r["vulnerable"] = True
                report = {
                    "call_address": rr["call_address"],
                    "storage_addresses": [],
                }
                r["spots"].append(report)
        return r
