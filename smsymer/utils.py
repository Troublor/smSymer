import subprocess
from typing import List

from z3 import BoolRef, Solver, Z3_L_TRUE, Z3_L_FALSE, is_expr

from local_test.disassemble import Instruction


def is_symbol(var):
    return is_expr(var)


def compile_sol(sol_filename):
    cmd = "solc --bin {0}".format(sol_filename)
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    is_bin = False
    lines = p.stdout.readlines()
    for line in lines:
        if is_bin:
            return str(line, encoding='utf-8').strip('\n')
        if "Binary" in str(line):
            is_bin = True
    print("\n".join(map(lambda l: str(l, encoding='utf-8'), lines)))
    raise AttributeError("Compile error")


def is_stack_safe(instructions: List[Instruction]):
    stack_depth = 0
    for ins in instructions:
        stack_depth -= ins.input_amount
        stack_depth += ins.output_amount
        if stack_depth < 0:
            raise AttributeError("Error stack {0}: {1}".format(stack_depth, str(ins)))


def cond_always_true(condition: BoolRef):
    s = Solver()
    s.add(condition)
    if s.check().r == Z3_L_TRUE and len(s.model()) == 0:
        return True
    return False


def cond_always_false(condition: BoolRef):
    s = Solver()
    s.add(condition)
    if s.check().r == Z3_L_FALSE:
        return True
    return False


if "sequence" not in globals():
    sequence = 0


def uuid() -> str:
    global sequence
    o = sequence
    sequence += 1
    return str(o)


def int2bytes(content, l_word=-1, type_=int) -> List:
    """
    Convert int to byte list
    :param type_: the type of every item in byte list
    :param content: int
    :param l_word: the length of bytes
    :return: List[type_]
    """
    if is_symbol(content):
        raise AttributeError("Can not convert symbolic value to bytes")
    r = []
    tmp = hex(int(content))[2:]
    if len(tmp) % 2 == 1:
        tmp = "0" + tmp
    tmp = tmp.ljust(l_word * 2, '0')
    for i in range(0, len(tmp), 2):
        if type_ == int:
            r.append(int(tmp[i:i + 1], 16))
        elif type_ == str:
            r.append(tmp[i:i + 1])
        else:
            r.append(type_(tmp[i:i + 1]))
    return r