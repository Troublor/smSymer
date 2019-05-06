from os import path, getcwd

import smsymer.utils as utils
from smsymer import SmSymer
from smsymer.evm import disasm


def test_timestamp_dependency0():
    cwd = getcwd()
    file = path.join(cwd, 'timestamp_dependency0.sol')
    bytecodes = utils.compile_sol(file)
    instructions = disasm(bytecodes)
    symer = SmSymer(instructions)
    assert symer.timestamp_dependency


def test_timestamp_dependency1():
    cwd = getcwd()
    file = path.join(cwd, 'timestamp_dependency1.sol')
    bytecodes = utils.compile_sol(file)
    instructions = disasm(bytecodes)
    symer = SmSymer(instructions)
    assert not symer.timestamp_dependency
