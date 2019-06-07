import os
import re
import subprocess
import sys
from typing import List, Dict, Tuple

from z3 import BoolRef, Solver, Z3_L_TRUE, Z3_L_FALSE, is_expr, z3

from conf import ROOT_DIR
from smsymer import Printer, DPrinter
from smsymer.evm import Instruction


def is_symbol(var):
    return is_expr(var)


def compile_sol(sol_filename, runtime=False) -> List[Tuple[str, str]]:
    # solc_path = os.path.join(ROOT_DIR, 'tools', "solc.exe")
    solc_path = "solc"
    if runtime:
        cmd = solc_path + " --bin-runtime {0}".format(sol_filename)
    else:
        cmd = solc_path + " --bin {0}".format(sol_filename)
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    is_bin = False
    lines = p.stdout.readlines()
    results = []
    contract_name = ""
    for line in lines:
        if is_bin:
            bytecode = str(line, encoding='utf-8').strip()
            if len(bytecode) > 0:
                results.append((contract_name, bytecode))
            is_bin = False
        match_obj = re.match(r'=======.*:(.*?)=======', str(line, encoding='utf-8'))
        if match_obj:
            contract_name = match_obj.group(1).strip()
        if "Binary" in str(line, encoding='utf-8'):
            is_bin = True
    if len(results) > 0:
        return results
    else:
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


def in_list(list: list, item) -> bool:
    for l in list:
        if is_symbol(l) and is_symbol(item):
            if z3.eq(l, item):
                return True
        elif not is_symbol(l) and not is_symbol(item):
            if int(l) == int(item):
                return True
    else:
        return False


def extract_z3_ref(ref) -> list:
    children = ref.children()
    if len(children) == 0:
        return [ref]
    else:
        results = []
        for child in children:
            results = results + extract_z3_ref(child)
        return results


def extract_z3_symbols(ref) -> list:
    result = []
    for r in extract_z3_ref(ref):
        if not is_z3_constant(r):
            result.append(r)
    return result


def is_z3_constant(ref) -> bool:
    return type(ref) is z3.IntNumRef


def eq(a, b) -> bool:
    if is_symbol(a):
        if is_symbol(b):
            return z3.eq(a, b)
        else:
            return False
    else:
        if is_symbol(b):
            return False
        else:
            return a == b
