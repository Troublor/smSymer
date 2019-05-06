import copy
from typing import Union

from Crypto.Hash import keccak

# 单字中包含的字节数
from z3 import BoolRef, Int, Not

from smsymer import utils
from smsymer.disassemble import Instruction

l_word = 4


class Word(object):
    def __init__(self, data):
        if type(data) == int:
            # 转换成字节并增加前缀0x
            _data = hex(data)
        elif type(data) == str:
            _data = data
            # 增加前缀0x
            if not data.startswith('0x'):
                _data = '0x' + _data
        else:
            raise AttributeError
        self._byte32 = self._parse_byte_str(_data)

    @staticmethod
    def _parse_byte_str(byte_str):
        """
        :param byte_str: 十六进制字符串, e.g., 0x123456
        :return: l_word个字节组成的list, e.g., ['00', '00', '12', '34', '56']
        """
        if len(byte_str) > l_word * 2 + 2:
            # 长度超过l_word个字节则会被截断
            byte_str = '0x' + byte_str[2:][0 - l_word * 2:]
        byte32 = ['00'] * l_word
        byte = byte_str[2:]
        if len(byte) % 2 != 0:
            byte = '0' + byte
        for i in range(int(len(byte) / 2)):
            byte32[-1 - i] = byte[len(byte) - 2 * i - 2] + byte[len(byte) - 2 * i - 1]
        return byte32

    @property
    def byte_str(self):
        return '0x' + ''.join(self._byte32)

    def __hash__(self):
        return hash(int(self))

    def __str__(self):
        return self.byte_str

    def __int__(self):
        return int(self.byte_str, 16)

    def __hex__(self):
        return hex(int(self))

    def __oct__(self):
        return oct(int(self))

    def __index__(self):
        return int(self)

    def __getitem__(self, item):
        if type(item) == slice:
            return self._byte32[item.start:item.stop:item.step]
        else:
            return self._byte32[item]

    def is_neg(self):
        return int(self._byte32[0], 16) & 0x80 != 0

    def __neg__(self):
        # 取反加一
        if self == Word('80' + '00' * (l_word - 1)):
            raise ArithmeticError
        new_word = Word(self.byte_str)
        for ii in range(l_word):
            new_word._byte32[ii] = hex(int(new_word._byte32[ii], 16) ^ 0xFF)[2:]
        new_word._byte32 = new_word._parse_byte_str(hex(int(new_word.byte_str, 16) + 1))
        return new_word

    def __abs__(self):
        if int(self._byte32[0], 16) & 0x80 == 0:
            # 首位为0，正数
            return self
        else:
            # 首位为1，负数
            return -self

    def __add__(self, other):
        return Word(int(self) + int(other))

    def __sub__(self, other):
        return Word(int(self) - int(other))

    def __mul__(self, other):
        return Word(int(self) - int(other))

    def __floordiv__(self, other):
        """
        //重载为有符号除法
        :type other Word
        """
        if int(other) == 0:
            return Word(0)
        elif other == Word('FF' * l_word):
            return Word('FF' * l_word)
        else:
            r = abs(self) / abs(other)
            if self.is_neg() ^ other.is_neg():
                # 两者异号
                r = -r
            return r

    def __truediv__(self, other):
        # /重载为无符号除法
        if int(other) == 0:
            return Word(0)
        return Word(int(self) // int(other))

    def __mod__(self, other):
        if int(other) == 0:
            return Word(0)
        else:
            return Word(int(self) % int(other))

    def smod(self, other):
        """
        有符号模
        :type other Word
        """
        if int(other) == 0:
            return Word(0)
        else:
            r = abs(self) % abs(other)
            if self.is_neg():
                r = -r
            return r

    def __pow__(self, power, modulo=None):
        return Word(int(self) ** int(power))

    def sign_extend(self, t):
        r = int(self)
        mask = int('0' * t + '1' + '0' * (l_word * 8 - t - 1), 2)
        sign = int(r & mask != 0)
        mask = int(str(sign) * t + '0' * (l_word * 8 - t), 2)
        r = r | mask
        return Word(r)

    def __lt__(self, other):
        if int(self) < int(other):
            return Word(1)
        else:
            return Word(0)

    def __gt__(self, other):
        if int(self) > int(other):
            return Word(1)
        else:
            return Word(0)

    def slt(self, other):
        if self.is_neg():
            if not other.is_neg():
                return Word(1)
            elif abs(self) > abs(other):
                return Word(1)
            else:
                return Word(0)
        elif other.is_neg():
            return Word(0)
        elif abs(self) < abs(other):
            return Word(1)
        else:
            return Word(0)

    def sgt(self, other):
        if self.slt(other) and self == other:
            return Word(0)
        else:
            return Word(1)

    def __eq__(self, other):
        if int(other) == int(self):
            return Word(1)
        else:
            return Word(0)

    def is_zero(self):
        if int(self) == 0:
            return Word(1)
        else:
            return Word(0)

    def __and__(self, other):
        return Word(int(self) & int(other))

    def __or__(self, other):
        return Word(int(self) | int(other))

    def __xor__(self, other):
        return Word(int(self) ^ int(other))

    def __invert__(self):
        b = bin(int(self))[2:]
        b = '0' * (l_word * 8 - len(b)) + b
        b = ''.join(map(lambda bit: str(int(bit) ^ 1), b))
        return Word(int(b, 2))

    def retrieve_byte(self, index):
        # index count from left
        if index < 32:
            return Word(self._byte32[index])
        else:
            return Word(0)


class Stack(object):
    def __init__(self):
        # list 尾部为栈顶
        self._stack = []

    def __len__(self):
        return len(self._stack)

    def __getitem__(self, item):
        return self._stack[item]

    def push(self, operand: Word):
        self._stack.append(operand)

    def pop(self) -> Union[Word, None]:
        if len(self._stack) < 1:
            return None
        out = self._stack[-1]
        self._stack = self._stack[:-1]
        return out

    def dup(self, index: int):
        item = self._stack[-index]
        self.push(item)

    def swap(self, index: int):
        item = self.pop()
        self.dup(index)
        self._stack[-index - 1] = item


class Memory(object):
    """
    自扩展的虚拟内存，字节寻址
    """

    def __init__(self):
        self._memory = []

    def _prepare_item(self, index):
        if len(self._memory) <= index:
            for i in range(index - len(self._memory) + 1):
                self._memory.append('00')

    def __getitem__(self, item):
        if type(item) == slice:
            s = []
            if item.step is None:
                for i in range(item.start, item.stop):
                    self._prepare_item(i)
                    s.append(self._memory[i])
            else:
                for i in range(item.start, item.stop, item.step):
                    self._prepare_item(i)
                    s.append(self._memory[i])
            return s
        else:
            if item < 0:
                raise AttributeError("Memory index can not be negative")
            self._prepare_item(item)
            return self._memory[item]

    def __setitem__(self, key, value):
        if key < 0:
            raise AttributeError("Memory index can not be negative")
        if type(value) == int:
            v = hex(value)[2:]
        elif type(value) == str:
            v = hex(int(value, 16))[2:]
        else:
            v = value
        # else:
        #     raise AttributeError("Invalid byte value: {0}".format(value))
        # if v > 0xff or v < 0:
        #     raise AttributeError("Invalid byte value: {0}".format(value))
        self._prepare_item(key)
        self._memory[key] = v


class MemoryItem(object):
    def __init__(self, start, length, content):
        self.start = start
        self.length = length
        self.content = content

    def conflicts_with(self, other):
        # if self will modify the content of other
        if utils.is_symbol(self.start) or utils.is_symbol(self.length) or utils.is_symbol(
                other.start) or utils.is_symbol(other.length):
            return False
        if self.start <= other.start < self.start + self.length or other.start <= self.start < other.start + other.length:
            return True
        else:
            return False


class HashMemory(object):
    def __init__(self):
        self._memory = {}
        # self.Ui = 0

    def load(self, start, length):
        if start not in self._memory.keys():
            return Int("M_{0}_{1}".format(start, length))
        tmp: MemoryItem = self._memory[start]
        if tmp.length == length:
            return tmp.content
        return Int("M_{0}_{1}".format(start, length))

    def store(self, start, length, content):
        tmp = MemoryItem(start, length, content)
        for addr, item in self._memory.copy().items():
            if tmp.conflicts_with(item):
                del self._memory[addr]
        self._memory[start] = tmp


class Storage(object):
    def __init__(self):
        self._storage = {}

    def __getitem__(self, item):
        if item not in self._storage.keys():
            self._storage[item] = Int("s_" + str(item))
        return self._storage[item]

    def __setitem__(self, key, value):
        self._storage[key] = value


class PcPointer(object):
    NEXT_ADDR = 0
    STOP = -1
    JUMP = 1
    JUMPI = 2

    def __init__(self, status, addr=None, cond=None):
        self.status = status
        self.addr = addr
        self.condition = cond


class VM(object):
    def __init__(self):
        # TODO limit the max depth of stack to 1024
        global l_word
        l_word = 32
        # current executing account
        # self.I_a = Int('Ia')
        # 用户账户
        self._balances = []
        # 运行栈
        self._stack: Stack = Stack()
        # Memory
        self._memory: HashMemory = HashMemory()
        # Storage
        self._storage: Storage = Storage()
        # 运行状态
        self._status = False
        # PC counter
        self._pc = 0

    def exe(self, instruction: Instruction) -> PcPointer:
        next_addr = None

        stack_depth = len(self._stack)

        if instruction.opcode.startswith("PUSH"):
            opr = getattr(self, "PUSH")
            opr(instruction.params)
        elif instruction.opcode.startswith("DUP"):
            opr = getattr(self, "DUP")
            opr(int(instruction.opcode[3:]))
        elif instruction.opcode.startswith("SWAP"):
            opr = getattr(self, "SWAP")
            opr(int(instruction.opcode[4:]))
        elif instruction.opcode.startswith("LOG"):
            opr = getattr(self, "SWAP")
            opr(int(instruction.opcode[3:]))
        else:
            opr = getattr(self, instruction.opcode)
            next_addr = opr()

        if stack_depth - instruction.input_amount + instruction.output_amount != len(self._stack):
            print("Execution Bug: {0}".format(str(instruction)))

        if next_addr is None:
            next_addr = PcPointer(PcPointer.NEXT_ADDR)
        self._pc += 1
        return next_addr

    @classmethod
    def init_state(cls) -> list:
        return [
            0,  # PC counter
            [
                Storage()
            ],
            [
                Stack(),
                HashMemory(),
            ]
        ]

    def backup(self):
        return [
            self.backup_pc(),
            self.backup_world_state(),
            self.backup_machine_state(),
        ]

    def retrieve(self, bak):
        self.retrieve_pc(bak[0])
        self.retrieve_world_state(bak[1])
        self.retrieve_machine_state(bak[2])

    def reset(self):
        self.reset_pc()
        self.reset_world_state()
        self.reset_machine_state()

    def backup_pc(self):
        return self._pc

    def retrieve_pc(self, bak):
        self._pc = bak

    def backup_world_state(self):
        s = copy.deepcopy(self._storage)
        world_state_bak = [s]
        return world_state_bak

    def retrieve_world_state(self, bak):
        self._storage = bak.pop()

    def backup_machine_state(self):
        s = copy.deepcopy(self._stack)
        m = copy.deepcopy(self._memory)
        machine_state_bak = [s, m]
        return machine_state_bak

    def retrieve_machine_state(self, bak):
        self._memory = bak.pop()
        self._stack = bak.pop()

    def reset_pc(self):
        self._pc = 0

    def reset_world_state(self):
        self._storage = Storage()

    def reset_machine_state(self):
        self._stack = Stack()
        self._memory = HashMemory()

    def _stack_pop(self):
        op = self._stack.pop()
        if type(op) is Word:
            op = int(op)
        if op is None:
            print(False)
        if type(op) is float:
            op = int(op)
        return op

    def _stack_push(self, op):
        self._stack.push(op)

    def STOP(self):
        self._status = False
        return PcPointer(PcPointer.STOP)

    def ADD(self):
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        self._stack_push(op1 + op0)

    def MUL(self):
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        self._stack_push(op0 * op1)

    def SUB(self):
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        self._stack_push(op0 - op1)

    def DIV(self):
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        self._stack_push(op0 / op1)

    def SDIV(self):
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        self._stack_push(op0 // op1)

    def MOD(self):
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        self._stack_push(op0 % op1)

    def SMOD(self):
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        self._stack_push(op0.smod(op1))

    def ADDMOD(self):
        # All intermediate calculations of this operation are not subject to the 2^256 modulo
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        op2 = self._stack_pop()
        if int(op2) == 0:
            self._stack_push(Word(0))
        else:
            self._stack_push(Word((int(op0) + int(op1)) % int(op2)))

    def MULMOD(self):
        # All intermediate calculations of this operation are not subject to the 2^256 modulo
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        op2 = self._stack_pop()
        if int(op2) == 0:
            self._stack_push(Word(0))
        else:
            self._stack_push(Word((int(op0) * int(op1)) % int(op2)))

    def EXP(self):
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        self._stack_push(op0 ** op1)

    def SIGNEXTEND(self):
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        t = l_word * 8 - 8 * (int(op0) + 1)
        self._stack_push(op1.sign_extend(t))

    def LT(self):
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        self._stack_push(op0 < op1)

    def GT(self):
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        self._stack_push(op0 > op1)

    def SLT(self):
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        self._stack_push(op0.slt(op1))

    def SGT(self):
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        self._stack_push(op0.sgt(op1))

    def EQ(self):
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        self._stack_push(op0 == op1)

    def ISZERO(self):
        op0 = self._stack_pop()
        if type(op0) is int:
            if op0 == 0:
                self._stack_push(Word(1))
            else:
                self._stack_push(Word(0))
        elif type(op0) is BoolRef:
            self._stack_push(Not(op0))
        else:
            self._stack_push(op0 == 0)

    def AND(self):
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        if utils.is_symbol(op0) or utils.is_symbol(op1):
            self._stack_push(Int(str(op0) + "&" + str(op1)))
        else:
            self._stack_push(op0 & op1)

    def OR(self):
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        if utils.is_symbol(op0) or utils.is_symbol(op1):
            self._stack_push(Int(str(op0) + "|" + str(op1)))
        else:
            self._stack_push(op0 | op1)

    def XOR(self):
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        if utils.is_symbol(op0) or utils.is_symbol(op1):
            self._stack_push(Int(str(op0) + "^" + str(op1)))
        else:
            self._stack_push(op0 ^ op1)

    def NOT(self):
        # TODO bug fix
        op0 = self._stack_pop()
        if utils.is_symbol(op0):
            self._stack_push(Int("~" + str(op0)))
        else:
            self._stack_push(~op0)

    def BYTE(self):
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        self._stack_push(op1.retrieve_byte(int(op0)))

    def SHL(self):
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        if not utils.is_symbol(op0) and not utils.is_symbol(op1):
            self._stack_push(op1 << op0)
        else:
            self._stack_push(Int("(" + op1 + " << " + op0 + ")"))

    def SHA3(self):
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        # m_slice = self._memory[int(op0):int(op0) + int(op1)]
        value = self._memory.load(int(op0), int(op1))
        if utils.is_symbol(value):
            self._stack_push(Int("SHA3_{0}".format(self._pc)))
        else:
            value = bytes(utils.int2bytes_string(value))
            keccak_hash = keccak.new(digest_bits=8 * l_word)
            keccak_hash.update(value)
            hash_value = keccak_hash.hexdigest()
            self._stack_push(Word(hash_value))
            return
        self._stack_push(Int("m_" + str(op0) + "_" + str(op1)))

    def ADDRESS(self):
        self._stack_push(Int("Ia"))

    def BALANCE(self):
        op0 = self._stack_pop()
        # 本意为获取地址为op0的账户余额
        # 这里实现为push一个symbol
        self._stack_push(Int("b_" + str(op0)))

    def ORIGIN(self):
        self._stack_push(Int("Io"))

    def CALLER(self):
        self._stack_push(Int("Is"))

    def CALLVALUE(self):
        self._stack_push(Int("Iv"))

    def CALLDATALOAD(self):
        op = self._stack_pop()
        # 本意为获取地址为op0的一个Word的call data
        # 这里实现为push一个symbol
        self._stack_push(Int("Id"))

    def CALLDATASIZE(self):
        self._stack_push(Int("s_Id"))

    def CALLDATACOPY(self):
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        op2 = self._stack_pop()
        self._memory.store(op0, op2, Int("Ib_{0}_{1}".format(op1, op2)))
        # if type(op0) is int and type(op2) is int:
        #     for i in range(op2):
        #         self._memory[op0 + i] = Int("Id_" + str(op1) + "_" + str(i))
        # else:
        #     raise VmExecutionException("Not supported: symbolic CALLDATACOPY")

    def CODESIZE(self):
        self._stack_push(Int("s_Ib"))

    def CODECOPY(self):
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        op2 = self._stack_pop()
        # 并不真正进行此操作

    def GASPRICE(self):
        self._stack_push(Int("Ip"))

    def EXTCODESIZE(self):
        raise VmExecutionException("Operation not supported: EXTCODESIZE")

    def EXTCODECOPY(self):
        raise VmExecutionException("Operation not supported: EXTCODECOPY")

    def RETURNDATASIZE(self):
        # raise VmExecutionException("Operation not supported: RETURNDATASIZE")
        self._stack_push(Int("s_Uo_{0}".format(self._pc)))

    def RETURNDATACOPY(self):
        # raise VmExecutionException("Operation not supported: RETURNDATACOPY")
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        op2 = self._stack_pop()
        self._memory.store(op0, op2, Int("Uo_{0}_{1}_{2}".format(self._pc, op1, op2)))

    def BLOCKHASH(self):
        op0 = self._stack_pop()
        self._stack_push(Int("IHp"))

    def COINBASE(self):
        self._stack_push(Int("IHc"))

    def TIMESTAMP(self):
        self._stack_push(Int("IHs"))

    def NUMBER(self):
        self._stack_push(Int("IHi"))

    def DIFFICULTY(self):
        self._stack_push(Int("IHd"))

    def GASLIMIT(self):
        self._stack_push(Int("IHl"))

    def MLOAD(self):
        op0 = self._stack_pop()
        word = self._memory.load(op0, 32)
        self._stack_push(word)
        # if type(op0) is not int:
        #     raise VmExecutionException("Not support symbolic MLOAD")
        # word = self._memory[op0:op0 + l_word]
        # for w in word:
        #     if utils.is_symbol(w):
        #         self._stack_push(Int("m_" + utils.uuid()))
        #         # raise VmExecutionException("Not support MLOAD load symbolic data")
        #         return
        # self._stack_push(Word('0x' + ''.join(word)))

    def MSTORE(self):
        op0 = self._stack_pop()
        op1 = self._stack.pop()
        self._memory.store(op0, 32, op1)
        # if type(op0) is not int:
        #     raise VmExecutionException("Not support symbolic MSTORE")
        # elif type(op1) is Word:
        #     for i in range(l_word):
        #         self._memory[op0 + i] = op1[i]
        # else:
        #     # raise VmExecutionException("Not support MSTORE strore symbolic data")
        #     for i in range(l_word):
        #         self._memory[op0 + i] = Int("m_" + utils.uuid())

    def MSTORE8(self):
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        self._memory.store(op0, 1, op1 % 256)
        # if type(op0) is not int:
        #     raise VmExecutionException("Not support symbolic MSTORE8")
        # elif utils.is_symbol(op1):
        #     # self._memory[op0] = Int("m_" + utils.uuid())
        #     raise VmExecutionException("Not support MSTORE8 store symbolic data")
        # else:
        #     self._memory[op0] = Word(int(op1) % 8 * l_word)[-1]

    def SLOAD(self):
        op0 = self._stack_pop()
        s = self._storage[op0]
        self._stack_push(self._storage[op0])

    def SSTORE(self):
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        self._storage[op0] = op1

    def JUMP(self) -> PcPointer:
        op0 = self._stack_pop()
        return PcPointer(PcPointer.JUMP, addr=op0)

    def JUMPI(self) -> PcPointer:
        """
        伪条件跳转
        :return: PcPointer
        """
        # TODO have problems with symbolic execution
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        if type(op1) == int:
            # 跳转目的地址确定
            if op1 != 0:
                return PcPointer(PcPointer.JUMP, addr=op0)
            else:
                return PcPointer(PcPointer.NEXT_ADDR)
        else:
            # 跳转地址不确定
            if utils.cond_always_true(op1):
                # constrain always true
                return PcPointer(PcPointer.JUMP, addr=op0)
            elif utils.cond_always_false(op1):
                return PcPointer(PcPointer.NEXT_ADDR)
            else:
                return PcPointer(PcPointer.JUMPI, addr=op0, cond=op1)

    def PC(self):
        self._stack_push(Word(self._pc))

    def MSIZE(self):
        # raise VmExecutionException("Operation not supported: MSIZE")
        self._stack_push(Int("32Ui_{0}".format(self._pc)))

    def GAS(self):
        # raise VmExecutionException("Operation not supported: GAS")
        self._stack_push(Int("Gi_{0}".format(self._pc)))

    def JUMPDEST(self):
        pass

    def POP(self):
        op0 = self._stack_pop()

    def PUSH(self, params):
        self._stack_push(Word('0x' + ''.join(params)))

    def DUP(self, index):
        self._stack.dup(index)

    def SWAP(self, index):
        self._stack.swap(index)

    def LOG(self, n):
        for i in range(n + 2):
            self._stack_pop()

    def CREATE(self):
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        op2 = self._stack_pop()
        self._stack_push(Int("CREATE_{0}".format(self._pc)))
        # raise VmExecutionException("Operation not supported: CREATE")

    def CALL(self):
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        op2 = self._stack_pop()
        op3 = self._stack_pop()
        op4 = self._stack_pop()
        op5 = self._stack_pop()
        op6 = self._stack_pop()
        self._stack_push(Int("call_{0}".format(self._pc)))

    def CALLCODE(self):
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        op2 = self._stack_pop()
        op3 = self._stack_pop()
        op4 = self._stack_pop()
        op5 = self._stack_pop()
        self._stack_push(Int("callcode_{0}".format(self._pc)))

    def STATICCALL(self):
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        op2 = self._stack_pop()
        op3 = self._stack_pop()
        op4 = self._stack_pop()
        op5 = self._stack_pop()
        self._stack_push(Int("staticcall_{0}".format(self._pc)))

    def RETURN(self):
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        return PcPointer(PcPointer.STOP)

    def DELEGATECALL(self):
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        op2 = self._stack_pop()
        op3 = self._stack_pop()
        op4 = self._stack_pop()
        op5 = self._stack_pop()
        op6 = self._stack_pop()
        self._stack_push(Int("delegatecall_{0}".format(self._pc)))

    def REVERT(self):
        op0 = self._stack_pop()
        op1 = self._stack_pop()
        return PcPointer(PcPointer.STOP)

    def INVALID(self):
        pass

    def SELFDESTRUCT(self):
        op0 = self._stack_pop()


class VmExecutionException(Exception):
    def __init__(self, msg):
        super().__init__(msg)


if __name__ == "__main__":
    pass
