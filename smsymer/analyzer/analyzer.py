import copy
from typing import List

from smsymer import Printer
from . import TimestampDepTracker, CallResultTracker, ReentrancyTracker
from smsymer.cfg import CFG, Block
from smsymer.evm import Instruction


class Analyzer:
    def __init__(self, instructions: List[Instruction], printer: Printer = Printer(Printer.CONSOLE), verbose=False):
        self.instructions = instructions
        self.printer = printer
        self.verbose = verbose
        c_blocks, b_blocks = self._construct_blocks()
        self.construct_cfg = CFG(c_blocks, printer, verbose)
        self.body_cfg = CFG(b_blocks, printer, verbose)

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
