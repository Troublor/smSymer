# schema: [opcode, ins, outs, gas, params]
from typing import Union, List

opcodes = {

    # arithmetic
    0x00: ['STOP', 0, 0, 0, 0],
    0x01: ['ADD', 2, 1, 3, 0],
    0x02: ['MUL', 2, 1, 5, 0],
    0x03: ['SUB', 2, 1, 3, 0],
    0x04: ['DIV', 2, 1, 5, 0],
    0x05: ['SDIV', 2, 1, 5, 0],
    0x06: ['MOD', 2, 1, 5, 0],
    0x07: ['SMOD', 2, 1, 5, 0],
    0x08: ['ADDMOD', 3, 1, 8, 0],
    0x09: ['MULMOD', 3, 1, 8, 0],
    0x0a: ['EXP', 2, 1, 10, 0],
    0x0b: ['SIGNEXTEND', 2, 1, 5, 0],

    # boolean
    0x10: ['LT', 2, 1, 3, 0],
    0x11: ['GT', 2, 1, 3, 0],
    0x12: ['SLT', 2, 1, 3, 0],
    0x13: ['SGT', 2, 1, 3, 0],
    0x14: ['EQ', 2, 1, 3, 0],
    0x15: ['ISZERO', 1, 1, 3, 0],
    0x16: ['AND', 2, 1, 3, 0],
    0x17: ['OR', 2, 1, 3, 0],
    0x18: ['XOR', 2, 1, 3, 0],
    0x19: ['NOT', 1, 1, 3, 0],
    0x1a: ['BYTE', 2, 1, 3, 0],
    0x1b: ['SHL', 2, 1, 3, 0],

    # crypto
    0x20: ['SHA3', 2, 1, 30, 0],

    # contract context
    0x30: ['ADDRESS', 0, 1, 2, 0],
    0x31: ['BALANCE', 1, 1, 20, 0],
    0x32: ['ORIGIN', 0, 1, 2, 0],
    0x33: ['CALLER', 0, 1, 2, 0],
    0x34: ['CALLVALUE', 0, 1, 2, 0],
    0x35: ['CALLDATALOAD', 1, 1, 3, 0],
    0x36: ['CALLDATASIZE', 0, 1, 2, 0],
    0x37: ['CALLDATACOPY', 3, 0, 3, 0],
    0x38: ['CODESIZE', 0, 1, 2, 0],
    0x39: ['CODECOPY', 3, 0, 3, 0],
    0x3a: ['GASPRICE', 0, 1, 2, 0],
    0x3b: ['EXTCODESIZE', 1, 1, 20, 0],
    0x3c: ['EXTCODECOPY', 4, 0, 20, 0],
    0x3d: ['RETURNDATASIZE', 0, 1, 2, 0],
    0x3e: ['RETURNDATACOPY', 3, 0, 3, 0],

    # blockchain context
    0x40: ['BLOCKHASH', 1, 1, 20, 0],
    0x41: ['COINBASE', 0, 1, 2, 0],
    0x42: ['TIMESTAMP', 0, 1, 2, 0],
    0x43: ['NUMBER', 0, 1, 2, 0],
    0x44: ['DIFFICULTY', 0, 1, 2, 0],
    0x45: ['GASLIMIT', 0, 1, 2, 0],

    # storage and execution
    0x50: ['POP', 1, 0, 2, 0],
    0x51: ['MLOAD', 1, 1, 3, 0],
    0x52: ['MSTORE', 2, 0, 3, 0],
    0x53: ['MSTORE8', 2, 0, 3, 0],
    0x54: ['SLOAD', 1, 1, 50, 0],
    0x55: ['SSTORE', 2, 0, 0, 0],
    0x56: ['JUMP', 1, 0, 8, 0],
    0x57: ['JUMPI', 2, 0, 10, 0],
    0x58: ['PC', 0, 1, 2, 0],
    0x59: ['MSIZE', 0, 1, 2, 0],
    0x5a: ['GAS', 0, 1, 2, 0],
    0x5b: ['JUMPDEST', 0, 0, 1, 0],

    # logging
    0xa0: ['LOG0', 2, 0, 375, 0],
    0xa1: ['LOG1', 3, 0, 750, 0],
    0xa2: ['LOG2', 4, 0, 1125, 0],
    0xa3: ['LOG3', 5, 0, 1500, 0],
    0xa4: ['LOG4', 6, 0, 1875, 0],

    # arbitrary length storage (proposal for metropolis hardfork)
    0xe1: ['SLOADBYTES', 3, 0, 50, 0],
    0xe2: ['SSTOREBYTES', 3, 0, 0, 0],
    0xe3: ['SSIZE', 1, 1, 50, 0],

    # closures
    0xf0: ['CREATE', 3, 1, 32000, 0],
    0xf1: ['CALL', 7, 1, 40, 0],
    0xf2: ['CALLCODE', 7, 1, 40, 0],
    0xf3: ['RETURN', 2, 0, 0, 0],
    0xf4: ['DELEGATECALL', 6, 1, 40, 0],
    # TODO STATICCALL gas consumption is not correct
    0xfa: ['STATICCALL', 6, 1, 0, 0],
    0xfd: ['REVERT', 2, 0, 0, 0],
    0xfe: ['INVALID', 0, 0, 0, 0],
    0xff: ['SELFDESTRUCT', 1, 0, 0, 0],
}

# push
for i in range(1, 33):
    opcodes[0x5f + i] = ['PUSH' + str(i), 0, 1, 3, i]

# duplicate and swap
for i in range(1, 17):
    opcodes[0x7f + i] = ['DUP' + str(i), i, i + 1, 3, 0]
    opcodes[0x8f + i] = ['SWAP' + str(i), i + 1, i + 1, 3, 0]


def get_operation_name(byte: int) -> Union[str, None]:
    if byte not in opcodes:
        return None
    return opcodes[byte][0]


def get_input_amount(byte: int) -> Union[int, None]:
    if byte not in opcodes:
        return None
    return opcodes[byte][1]


def get_output_amount(byte: int) -> Union[int, None]:
    if byte not in opcodes:
        return None
    return opcodes[byte][2]


def get_operation_gas(byte: int) -> Union[int, None]:
    if byte not in opcodes:
        return None
    return opcodes[byte][3]


def get_param_amount(byte: int) -> Union[int, None]:
    if byte not in opcodes:
        return None
    return opcodes[byte][4]


class Instruction(object):
    def __init__(self, addr: int = -1, bytecode: int = -1, opcode: str = "", params: List[str] = None):
        # address is not necessary in each case
        self.addr = addr
        # bytecode and opcode, only need one
        self.opcode = opcode
        self.bytecode = bytecode
        if self.opcode == "" and self.bytecode >= 0:
            self.opcode = get_operation_name(self.bytecode)
        elif self.opcode != "" and self.bytecode == -1:
            self.bytecode = self.get_operation_bytecode(self.opcode)
        if get_operation_name(self.bytecode) != self.opcode:
            raise InvalidOperationException(self.bytecode)
        if get_param_amount(self.bytecode) != 0 and params is None:
            raise InsufficientInputException(self.bytecode, 0, get_param_amount(self.bytecode))
        if params is None:
            params = []
        self.params = list(map(lambda s: s.rjust(2, '0'), params))

    @staticmethod
    def get_operation_bytecode(name: str) -> Union[int, None]:
        for bytecode, operation in opcodes.items():
            if operation[0] == name:
                return bytecode
        return None

    @property
    def input_amount(self) -> int:
        return get_input_amount(self.bytecode)

    @property
    def output_amount(self) -> int:
        return get_output_amount(self.bytecode)

    def __str__(self):
        if self.opcode is None:
            return "{0} {1}".format(hex(self.addr), "Invalid")
        elif len(self.params) > 0:
            return "{0} {1} {2}".format(hex(self.addr), self.opcode, "0x" + "".join(self.params))
        else:
            return "{0} {1}".format(hex(self.addr), self.opcode)


class InvalidOperationException(Exception):
    def __init__(self, byte):
        self.byte = byte

    def __str__(self):
        return "Invalid bytecode: {0}".format(self.byte)


class InsufficientInputException(Exception):
    def __init__(self, byte, got_amount, expected_amount):
        self.byte = byte
        self.got_amount = got_amount
        self.expected_amount = expected_amount

    def __str__(self):
        return "Insufficient Input for operation {0}({1}): expected_amount={2}, got_amount={3}".format(
            get_operation_name(self.byte), hex(self.byte), self.expected_amount, self.got_amount)


class ByteCode(object):
    _index = 0
    _bytecode = ''

    @classmethod
    def _reset(cls):
        """
        重置指针
        :return:
        """
        cls._index = 0

    @classmethod
    def _next_byte(cls) -> Union[int, None]:
        """
        获取下一个要处理的byte
        :return: 没有下一个了就返回None
        """
        if cls._index >= len(cls._bytecode):
            return None
        next_str = cls._bytecode[cls._index:cls._index + 2]
        cls._index += 2
        return cls._str2byte(next_str)

    @staticmethod
    def _str2byte(s: str) -> int:
        """
        16进制字符串转int
        :param s: 16进制字符串
        :return:
        :raise InsufficientInputException
        """
        return int(s, 16)

    @classmethod
    def disasm(cls, bytecode: str) -> List[Instruction]:
        if len(bytecode) % 2 != 0:
            raise AttributeError("Invalid byte code")
        if bytecode.startswith("0x"):
            bytecode = bytecode[2:]
        cls._bytecode = bytecode
        # start disassemble
        instructions: List[Instruction] = []
        cls._reset()
        byte = cls._next_byte()
        while byte is not None:
            address = int((cls._index - 2) / 2)
            n_param = get_param_amount(byte)
            if n_param is None:
                n_param = 0
                # raise InvalidOperationException(byte)
            inputs = []
            for ii in range(n_param):
                next_byte = cls._next_byte()
                if next_byte is None:
                    # raise InsufficientInputException(byte, ii + 1, n_param)
                    return instructions
                inputs.append(hex(next_byte)[2:])
            instructions.append(Instruction(address, byte, get_operation_name(byte), inputs))
            byte = cls._next_byte()
        return instructions


if __name__ == '__main__':
    ops = ByteCode(
        "606060405260968060106000396000f360606040526000357c0100000000000000000000000000000000000000000000000000000000900480635ec01e4d146037576035565b005b604260048050506058565b6040518082815260200191505060405180910390f35b60006000600060006005420643420204925082600061012c420660034304010101915081406001900490506001606482060193506090565b5050509056").instructions
    for op in ops:
        print(op)
