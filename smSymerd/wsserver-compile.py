import asyncio
import json
import os
import subprocess
import sys
import time
from typing import List, Tuple

import websockets

from smsymer import utils, Printer
from smsymer.analyzer import Analyzer
from smsymer.cfg import CFG
from smsymer.evm import ByteCode, Instruction
from smsymerd.debugger import Debugger
from smsymerd.model import instruction
from smsymerd.wprinter import WPrinter


async def serve(websocket, path):
    w_printer = WPrinter(websocket)
    debugger = Debugger()
    while True:
        data = await websocket.recv()
        data = json.loads(data)
        if "identifier" not in data:
            data["identifier"] = ""
        if data["operation"] == "solc":
            bytecode = solc(w_printer, data["data"], bool(data["options"]["optimization"]),
                            bool(data["options"]["runtime"]))
            resp = {
                "operation": "return-solc",
                "data": {
                    "bytecode": bytecode,
                },
                "identifier": data["identifier"]
            }
            await websocket.send(json.dumps(resp))
        elif data["operation"] == "disasm":
            bytecode = data["data"]["bytecode"]
            instructions = disasm(w_printer, bytecode)
            resp = {
                "operation": "return-disasm",
                "data": instructions,
                "identifier": data["identifier"]
            }
            await websocket.send(json.dumps(resp))
        elif data["operation"] == "debug":
            if data["type"] == "reset":
                debugger.reset()
            elif data["type"] == "execute":
                instructions = data["data"]
                debugger.execute(
                    map(lambda ins: Instruction(addr=ins["address"], opcode=ins["opcode"], bytecode=ins["bytecode"],
                                                params=ins["params"]), instructions))
                resp = {
                    "operation": "return-execute",
                    "data": debugger.get_status(),
                    "identifier": data["identifier"]
                }
                await websocket.send(json.dumps(resp))
        elif data["operation"] == "analyze":
            instructions = list(map(
                lambda ins: Instruction(addr=ins["address"], opcode=ins["opcode"], bytecode=ins["bytecode"],
                                        params=ins["params"]), data["data"]))
            vuls = analyze(WPrinter(websocket, identifier="analyze-log"), instructions)
            resp = {
                "operation": "return-analyze",
                "data": vuls,
                "identifier": data["identifier"],
            }
            await websocket.send(json.dumps(resp))


def analyze(printer: WPrinter, instructions: List[Instruction]) -> List[dict]:
    analyzer = Analyzer(instructions, printer, True)
    return analyze_cfg(analyzer.construct_cfg) + analyze_cfg(analyzer.body_cfg)


def analyze_cfg(cfg: CFG) -> List[dict]:
    resp = []
    timestamp_dependency_report = cfg.check_timestamp_dependency()
    if timestamp_dependency_report["vulnerable"]:
        for report in timestamp_dependency_report["spots"]:
            vul = {
                "type": "timestamp_dependency",
                "timestamp_address": str(cfg.get_instruction(report["timestamp_address"])),
                "dependency_address": str(cfg.get_instruction(report["dependency_address"])),
            }
            resp.append(vul)

    uncheck_call_report = cfg.check_unchecked_call()
    if uncheck_call_report["vulnerable"]:
        for report in uncheck_call_report["spots"]:
            vul = {
                "type": "uncheck_call",
                "call_address": str(cfg.get_instruction(report["call_address"])),
            }
            resp.append(vul)

    reentrancy_report = cfg.check_reentrancy()
    if reentrancy_report["vulnerable"]:
        for report in reentrancy_report["spots"]:
            vul = {
                "type": "reentrancy",
                "call_address": str(cfg.get_instruction(report["call_address"])),
                "guard_storage_variables": list(
                    map(lambda a: str(cfg.get_instruction(a)), report["storage_addresses"])),
            }
            resp.append(vul)
    return resp


def disasm(printer: WPrinter, bytecode: str) -> List[dict]:
    instructions = ByteCode.disasm(bytecode, printer)
    return list(map(lambda ins: instruction.dict_encode(ins), instructions))


def solc(printer: WPrinter, data: dict, optimization, runtime):
    tmp_file = os.path.join(sys.path[0], "tmp", utils.uuid())
    with open(tmp_file, "w+") as tmp_f:
        tmp_f.write(data["sourceCode"])
    solc_path = os.path.join(sys.path[0], "..", 'tools', "solc.exe")
    cmd = solc_path
    if optimization:
        cmd += " --optimize"
    cmd += " --bin"
    if runtime:
        cmd += "-runtime"
    cmd += " " + tmp_file
    full_bytecode = None
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    is_bin = False
    lines = p.stdout.readlines()
    for line in lines:
        if not runtime:
            printer.print(str(line, encoding='ansi'))
        if is_bin:
            full_bytecode = str(line, encoding='ansi').strip()
            break
        if "Binary" in str(line):
            is_bin = True
    else:
        printer.error("Compile error")
    return full_bytecode


start_server = websockets.serve(serve, 'localhost', 1110)

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
