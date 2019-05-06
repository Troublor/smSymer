from smsymer.evm import Instruction, EVM
from smsymer.evm.fact import opcodes


def test_stack():
    evm = EVM()
    for byte, code in opcodes.items():
        evm.reset()
        for i in range(code[1]):
            evm.PUSH('01')
        instruction = Instruction(opcode=code[0], params="01"*code[4])
        if instruction.opcode.startswith("PUSH"):
            instruction.params = "00" * (byte - 0x5f)
            opr = getattr(evm, "PUSH")
            opr(instruction.params)
        elif instruction.opcode.startswith("DUP"):
            opr = getattr(evm, "DUP")
            opr(int(instruction.opcode[3:]))
        elif instruction.opcode.startswith("SWAP"):
            opr = getattr(evm, "SWAP")
            opr(int(instruction.opcode[4:]))
        elif instruction.opcode.startswith("LOG"):
            opr = getattr(evm, "LOG")
            opr(int(instruction.opcode[3:]))
        else:
            opr = getattr(evm, instruction.opcode)
            opr()
        assert len(evm._stack) == code[2]
