import json
import os
import sys
import uuid

from flask import Flask, send_file, request

from smsymer import utils
from smsymer.evm import ByteCode
from smsymerd.model import instruction

app = Flask(__name__)

tmp_dir = os.path.join(sys.path[0], 'smsymerd', 'tmp')


@app.route("/", methods=["GET"])
@app.route("/smsymer")
def main():
    return send_file('index.html')


@app.route("/smsymer/disasm", methods=["POST"])
def disasm():
    bytecode = request.form['bytecode']
    resp = {
        "success": False,
        "info": "",
        "data": [],
    }
    try:
        instructions = ByteCode.disasm(bytecode)
        resp["success"] = True
        resp["data"] = list(map(lambda ins: instruction.dict_encode(ins), instructions))
    except Exception as e:
        resp["success"] = False
        resp["info"] = str(e)
    return json.dumps(resp)


@app.route("/smsymer/debugger", methods=["GET", "POST"])
def debug():
    if request.method == "GET":
        return send_file('debugger.html')
    else:
        pass
