from typing import List

from smsymer import utils
from smsymer.evm import Instruction, EVM


class Debugger(object):
    def __init__(self):
        self._evm = EVM()
        self._pc = 0

    def reset(self):
        self._pc = 0
        self._evm = EVM()

    def get_status(self):
        resp = {
            "storage": [],
            "memory": [],
            "stack": [],
        }

        for key, value in self._evm.get_storage().items():
            resp["storage"].append((hex(key), str(value)))
        for value in self._evm.get_memory().values():
            resp["memory"].append((hex(value.start), hex(value.length), str(value.content)))
        for item in reversed(self._evm.get_stack()):
            if utils.is_symbol(item):
                resp["stack"].append(str(item))
            else:
                resp["stack"].append(hex(int(item))[2:].rjust(64, '0'))
        return resp

    def execute(self, instructions):
        for ins in instructions:
            self._evm.exe(ins)
