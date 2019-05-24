from typing import Union, List

from smsymer import Printer
from smsymer.evm import Instruction
from smsymer.evm.exception import InsufficientInputException
from smsymer.evm.fact import get_param_amount, get_operation_name


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
        if cls._index + 2 > len(cls._bytecode):
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
    def disasm(cls, bytecode: str, printer: Union[None, Printer] = None) -> List[Instruction]:
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
                    if printer is None:
                        print("[WARN] incomplete push instruction at {0}".format(address))
                    else:
                        printer.warn("incomplete push instruction at {0}".format(address))
                    return instructions
                inputs.append(hex(next_byte)[2:])
            instructions.append(Instruction(address, byte, get_operation_name(byte), inputs))
            byte = cls._next_byte()
        return instructions
