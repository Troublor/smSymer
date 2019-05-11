from os import path, getcwd

import smsymer.utils as utils
from smsymer.analyzer import Analyzer
from smsymer.evm import disasm


def test_timestamp_dependency0():
    cwd = getcwd()
    file = path.join(cwd, 'timestamp_dependency0.sol')
    bytecodes = utils.compile_sol(file)
    instructions = disasm(bytecodes)
    symer = Analyzer(instructions)
    assert symer.body_cfg.check_timestamp_dependency()["vulnerable"]


def test_timestamp_dependency1():
    cwd = getcwd()
    file = path.join(cwd, 'timestamp_dependency1.sol')
    bytecodes = utils.compile_sol(file)
    instructions = disasm(bytecodes)
    symer = Analyzer(instructions)
    assert not symer.body_cfg.check_timestamp_dependency()["vulnerable"]


def test_unchecked_call0():
    cwd = getcwd()
    file = path.join(cwd, 'unchecked_call0.sol')
    bytecodes = utils.compile_sol(file)
    instructions = disasm(bytecodes)
    symer = Analyzer(instructions)
    assert symer.body_cfg.check_unchecked_call()["vulnerable"]


def test_unchecked_call1():
    cwd = getcwd()
    file = path.join(cwd, 'unchecked_call1.sol')
    bytecodes = utils.compile_sol(file)
    instructions = disasm(bytecodes)
    symer = Analyzer(instructions)
    assert not symer.body_cfg.check_unchecked_call()["vulnerable"]


def test_unchecked_call2():
    cwd = getcwd()
    file = path.join(cwd, 'unchecked_call2.sol')
    bytecodes = utils.compile_sol(file)
    instructions = disasm(bytecodes)
    symer = Analyzer(instructions)
    assert symer.body_cfg.check_unchecked_call()["vulnerable"]


def test_reentrancy0():
    cwd = getcwd()
    file = path.join(cwd, 'reentrancy0.sol')
    bytecodes = utils.compile_sol(file)
    instructions = disasm(bytecodes)
    symer = Analyzer(instructions)
    assert not symer.body_cfg.check_reentrancy()["vulnerable"]


def test_reentrancy1():
    cwd = getcwd()
    file = path.join(cwd, 'reentrancy1.sol')
    bytecodes = utils.compile_sol(file)
    instructions = disasm(bytecodes)
    symer = Analyzer(instructions)
    assert not symer.body_cfg.check_reentrancy()["vulnerable"]


def test_reentrancy2():
    cwd = getcwd()
    file = path.join(cwd, 'reentrancy2.sol')
    bytecodes = utils.compile_sol(file)
    instructions = disasm(bytecodes)
    symer = Analyzer(instructions)
    assert symer.body_cfg.check_reentrancy()["vulnerable"]


def test_reentrancy3():
    cwd = getcwd()
    file = path.join(cwd, 'reentrancy3.sol')
    bytecodes = utils.compile_sol(file)
    instructions = disasm(bytecodes)
    symer = Analyzer(instructions)

    assert symer.body_cfg.check_reentrancy()["vulnerable"]
