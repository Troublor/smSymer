class Instruction {
    constructor(address, bytecode, opcode, params) {
        this.address = address;
        this.bytecode = bytecode;
        this.opcode = opcode;
        this.params = params;
    }

    toString() {
        if (this.params.length === 0) {
            return this.opcode;
        } else {
            return this.opcode + " 0x" + this.params.join("");
        }
    }
}

function disasmAsync(bytecode) {
    return new Promise(function (resolve, reject) {
        $.post(
            "/smsymer/disasm",
            {
                bytecode: bytecode,
            },
            function (resp) {
                resp = eval("(" + resp + ")");
                let instructions = [];
                if (resp.success) {
                    resp.data.forEach(function (item) {
                        instructions.push(new Instruction(item.address, item.bytecode, item.opcode, item.params));
                    });
                    resolve(instructions);
                } else {
                    reject(resp.info);
                }
            }
        );
    });
}