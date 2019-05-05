from smsymer.disassemble import ByteCode, InsufficientInputException


def test_correct_code():
    bytecode = "606060405260968060106000396000f3"
    instructions = ByteCode.disasm(bytecode)
    assert instructions[-1].opcode == "RETURN"


def test_correct_code1():
    bytecode = "0x606060405260968060106000396000f3"
    instructions = ByteCode.disasm(bytecode)
    assert instructions[-1].opcode == "RETURN"


def test_wrong_code():
    bytecode = "606060405260968060106000396000f"
    try:
        ByteCode.disasm(bytecode)
        assert False
    except AttributeError as e:
        assert str(e) == "Invalid byte code"


def test_wrong_code1():
    bytecode = "606060405260968060106000396200"
    try:
        ByteCode.disasm(bytecode)
        assert False
    except InsufficientInputException:
        assert True


def test_wrong_code2():
    bytecode = "60606040cc"
    instructions = ByteCode.disasm(bytecode)
    assert "Invalid" in str(instructions[-1])
