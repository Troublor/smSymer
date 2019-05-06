import copy

from Crypto.Hash import keccak
from z3 import BoolRef, Not, Int

from smsymer import utils
from .word import Word
from .instruction import Instruction
from .stack import Stack
from .hashMemory import HashMemory
from .storage import Storage
from .pcPointer import PcPointer
from .exception import EvmExecutionException


class EVM(object):
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
        if not utils.is_symbol(op0) and not utils.is_symbol(op1):
            self._stack_push(Word(op0).smod(Word(op1)))
        else:
            raise EvmExecutionException("SMOD not support symbolic execution")

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
            value = bytes(utils.int2bytes(value))
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
        raise EvmExecutionException("Operation not supported: EXTCODESIZE")

    def EXTCODECOPY(self):
        raise EvmExecutionException("Operation not supported: EXTCODECOPY")

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