from smsymer.analyzer.tool import RefTracker
from smsymer.evm import Instruction, Stack
import smsymer.utils as utils


class ReentrancyTracker(RefTracker):
    # track the storage variable and see if it is used in the path condition of a CALL operation.
    def __init__(self, addr: int, height: int, storage_addr):
        super().__init__(addr, height)
        self.storage_addr = storage_addr

        self.after_used_in_condition = False
        self.after_call = False

        self.storage_changed = False

        self.gas_guarded = False
        self.value0 = False

        self.changed_after_condition = False
        self.changed_before_call = False

        self.buggy = False

        self.checked_calls = []
        self.vulnerable_calls = []

    def __eq__(self, other):
        return self.storage_addr == other.storage_addr

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.addr)

    @property
    def is_buggy(self):
        return self.buggy

    def op(self, instruction: Instruction, stack: Stack):
        # cases that storage variables are used in the path condition of a CALL operation
        if instruction.opcode == "JUMPI":
            # make sure that the condition is the direct condition of CALL, WRONG, but may have false positives...
            # self.used = False
            # check if current condition contains Storage variable
            self.use(instruction, len(stack))
            if self.used is True:
                self.after_used_in_condition = True
        elif instruction.opcode in ["CALL", "STATICCALL", "DELEGATECALL", "CALLCODE"]:
            self.checked_calls.append(instruction.addr)
            # check the gas forwarded
            self.pop(instruction.input_amount, len(stack))
            self.new(len(stack) - instruction.input_amount)
            gas = stack[-1]
            value = stack[-3]
            to = stack[-2]
            if not utils.is_symbol(to):
                # 如果目的地址是一个确定的值，说明接收人是可信的
                return
            if not utils.is_symbol(gas) and (int(gas) == 0 or int(gas) == 2300):
                self.gas_guarded = True
                return
            if '2300' in str(gas):
                self.gas_guarded = True
                return
            if value == 0:
                self.value0 = True
                return
                # There is no reentrancy bug only when some storage values used in path conditions
                # are changed after the condition and before the call operation
            if not self.changed_after_condition or not self.changed_before_call:
                self.buggy = True
                self.vulnerable_calls.append(instruction.addr)
                # clear detection history, be prepare for the next reentrancy
                self.after_call = False
                self.changed_before_call = False
                return
            self.after_call = True
        else:
            self.pop(instruction.input_amount, len(stack))
