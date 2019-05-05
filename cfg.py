import copy
from functools import reduce
from typing import List, Tuple, Union, Dict

from z3 import Solver, Not

from analysisVM import AnalysisVM, TimestampDepTracker, RefTracker, CallResultTracker, ReentrancyTracker
from disassemble import Instruction
from executor import VM, PcPointer

recursion_depth = 0


class Block(object):
    """
    Node in Control Flow Graph
    """

    def __init__(self, instructions: List[Instruction]):
        self.instructions = instructions

    @property
    def address(self) -> int:
        return self.instructions[0].addr

    @property
    def lass_address(self) -> int:
        return self.instructions[-1].addr

    def __str__(self):
        return hex(self.address)

    def __getitem__(self, item):
        if type(item) is int:
            return self.instructions[item]
        else:
            raise AttributeError("Block instructions do not support slice")

    def __eq__(self, other):
        return self.address == other.address

    def __ne__(self, other):
        return self.address != other.address

    def __len__(self):
        return len(self.instructions)

    def contains_call(self) -> bool:
        for ins in self.instructions:
            if ins.opcode in ["CALL", "STATICCALL", "DELEGATECALL", "CALLCODE"]:
                return True
        else:
            return False


class Transition(object):
    """
    Transition from basic block0 to basic block1
    """

    def __init__(self, from_: Block, to_: Block, constrain):
        """
        Initialization function
        :param from_: Transition is from block0 to block1
        :param to_: Transition is from block0 to block1
        :param constrain: Z3 constrains, transition happens when constrains are satisfied
        """
        self.constrain = constrain
        self.from_ = from_
        self.to_ = to_

    def __str__(self):
        return "{0} -> {1}, {2}".format(hex(self.from_.address), hex(self.to_.address), self.constrain)


class AnalyzeReport(object):
    def __init__(self):
        self.timestamp_dependency = False


class Analyzer(object):
    def __init__(self, instructions: List[Instruction]):
        self.instructions = instructions
        c_blocks, b_blocks = self._construct_blocks()
        self.construct_cfg = CFG(c_blocks)
        self.body_cfg = CFG(b_blocks)
        self.report = AnalyzeReport()

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


class CFG(object):
    """
    Control Flow Graph
    """

    def __init__(self, blocks: List[Block]):
        self.blocks = blocks

        self.transitions: List[Transition] = []
        self._construct_state = []
        self.vm = AnalysisVM()
        self.buggy_refs: Dict[int, RefTracker] = {}

        # the world and machine state when branch start. key is the last_address of branch block
        self.branch_entry_state: Dict[int, List] = {}

        self.block_dict: Dict[int: Block] = {}
        for block in self.blocks:
            self.block_dict[block.address] = block

        self._build_transitions()

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
        def _traverse_block_recursively(pc_b):
            global recursion_depth
            block = self.blocks[pc_b]
            print("Traverse block {0}".format(block))
            pc_i = 0
            while True:
                ins = block[pc_i]
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
                    print("END AT-" + str(block) + "-" + str(recursion_depth))
                    bak = self.vm.backup()
                    self.branch_entry_state[block.lass_address] = copy.deepcopy(bak)
                    break
                elif pc_pointer.status == PcPointer.JUMP:
                    last_block = self.blocks[pc_b]
                    bak = self.vm.backup()
                    self.branch_entry_state[last_block.lass_address] = copy.deepcopy(bak)
                    pc_bb = self._get_block_index(pc_pointer.addr)
                    if pc_bb is None:
                        print(False)
                    is_loop = self._add_transition(last_block, self.blocks[pc_bb])
                    if not is_loop:
                        _traverse_block_recursively(pc_bb)
                    # print("Jump to block: {0}".format(self.blocks[pc_bb]))
                    break
                elif pc_pointer.status == PcPointer.JUMPI:
                    recursion_depth += 1

                    last_block = self.blocks[pc_b]
                    print("BRANCH-AT-" + str(last_block) + "-" + str(recursion_depth) + "-" + str(pc_pointer.condition))
                    bak = self.vm.backup()
                    self.branch_entry_state[last_block.lass_address] = copy.deepcopy(bak)

                    # suppose condition is true
                    pc_bb = self._get_block_index(pc_pointer.addr)
                    if pc_bb is None:
                        print(False)
                    is_loop = self._add_transition(last_block, self.blocks[pc_bb], pc_pointer.condition)
                    if not is_loop:
                        print("BRANCH-1: {0}".format(self.blocks[pc_bb]))
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
                        print("BRANCH-2: {0}".format(self.blocks[pc_bb]))
                        _traverse_block_recursively(pc_bb)
                    print("END-BRANCH-" + str(recursion_depth))
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
