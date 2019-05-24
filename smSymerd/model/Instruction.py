import json

from smsymer.evm import Instruction


def dict_encode(ins: Instruction) -> dict:
    return {
        "address": ins.addr,
        "bytecode": ins.bytecode,
        "opcode": ins.opcode,
        "params": ins.params
    }


def dict_decode(ins: dict) -> Instruction:
    return Instruction(
        addr=ins["address"],
        opcode=ins["opcode"],
        bytecode=ins["bytecode"],
        params=ins["params"]
    )


def json_encode(ins: Instruction) -> str:
    return json.dumps(dict_encode(ins))


def json_decode(ins: str) -> Instruction:
    return dict_decode(json.loads(ins))
