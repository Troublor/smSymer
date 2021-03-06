# length of word
from typing import Union

l_word = 32

# schema: [opcode, ins, outs, gas, params]
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
    # 0xe1: ['SLOADBYTES', 3, 0, 50, 0],
    # 0xe2: ['SSTOREBYTES', 3, 0, 0, 0],
    # 0xe3: ['SSIZE', 1, 1, 50, 0],
    0xbb: ['BREAKPOINT', 0, 0, 0, 0],

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


def get_bytecode(op: str) -> Union[int, None]:
    for bytecode, opcode in opcodes.items():
        if opcode == op:
            return bytecode
    return None
