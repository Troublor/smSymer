from smsymer.analyzer.tool import RefTracker
from smsymer.evm import Instruction, Stack
import smsymer.utils as utils


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

    def op(self, instruction: Instruction, stack: Stack):
        # cases that storage variables are used in the path condition of a CALL operation
        if instruction.opcode == "JUMPI":
            self.use(instruction, len(stack))
        elif instruction.opcode in ["CALL", "STATICCALL", "DELEGATECALL", "CALLCODE"]:
            # check the gas forwarded
            gas = stack[-1]
            if not utils.is_symbol(gas) and (int(gas) == 0 or int(gas) == 2300):
                return
            if '2300' in str(gas):
                return
            self.contains_call = True
        else:
            self.pop(instruction.input_amount, len(stack))
