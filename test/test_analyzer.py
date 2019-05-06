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


def test_unchecked_call0():
    cwd = getcwd()
    file = path.join(cwd, 'unchecked_call0.sol')
    bytecodes = utils.compile_sol(file)
    instructions = disasm(bytecodes)
    symer = SmSymer(instructions)
    assert symer.unchecked_call


def test_unchecked_call1():
    cwd = getcwd()
    file = path.join(cwd, 'unchecked_call1.sol')
    bytecodes = utils.compile_sol(file)
    instructions = disasm(bytecodes)
    symer = SmSymer(instructions)
    assert not symer.unchecked_call


def test_unchecked_call2():
    cwd = getcwd()
    file = path.join(cwd, 'unchecked_call2.sol')
    bytecodes = utils.compile_sol(file)
    instructions = disasm(bytecodes)
    symer = SmSymer(instructions)
    assert symer.unchecked_call


def test_reentrancy0():
    cwd = getcwd()
    file = path.join(cwd, 'reentrancy0.sol')
    bytecodes = utils.compile_sol(file)
    instructions = disasm(bytecodes)
    symer = SmSymer(instructions)
    assert not symer.reentrancy


def test_reentrancy1():
    cwd = getcwd()
    file = path.join(cwd, 'reentrancy1.sol')
    bytecodes = utils.compile_sol(file)
    instructions = disasm(bytecodes)
    symer = SmSymer(instructions)
    assert not symer.reentrancy


def test_reentrancy2():
    cwd = getcwd()
    file = path.join(cwd, 'reentrancy2.sol')
    bytecodes = utils.compile_sol(file)
    instructions = disasm(bytecodes)
    symer = SmSymer(instructions)
    assert symer.reentrancy
