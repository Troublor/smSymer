let ws = new WebSocket("ws://localhost:1110");

let instructions = null;
let bytecode = null;
let debug_pointer = null; // point to next instruction to execute
let breakpoints = [];


ws.onclose = function (event) {
    alert("websocket closed");
};

ws.onmessage = function (event) {
    // console.log(event.data);
    let data = eval("(" + event.data + ")");
    switch (data["operation"]) {
        case "log":
            let log;
            if (data["identifier"] === "analyze-log") {
                log = $("#analyzeLog");
            } else {
                log = $("#log");
            }
            switch (data["type"]) {
                case "normal":
                    log.append("<p class='normal'>" + data["data"] + "</p>");
                    break;
                case "info":
                    log.append("<p class='info'>" + data["data"] + "</p>");
                    break;
                case "warn":
                    log.append("<p class='warn'>" + data["data"] + "</p>");
                    break;
                case "error":
                    log.append("<p class='error'>" + data["data"] + "</p>");
                    break;
            }
            $('#log').animate({
                    scrollTop: $("#log")[0].scrollHeight
                }, 0);
            break;
        case "return-solc":
            bytecode = data["data"]["bytecode"];
            if (bytecode !== null) {
                $("#bytecode").val(bytecode);
                let req = {
                    "operation": "disasm",
                    "data": {
                        "bytecode": bytecode
                    },
                    "identifier": "contract-code",
                };
                ws.send(JSON.stringify(req));
            }
            break;
        case "return-disasm":
            if (data["identifier"] === "contract-code") {
                $("#debugBtn").attr("disabled", false);
                $("#analyzeBtn").attr("disabled", false);
            }
            instructions = data["data"];
            $("#assemblyView").html("");
            $("#lineNumber").html("");
            instructions.forEach(function (item, index) {
                let s = item.opcode + " ";
                for (let i = 0; i < item.params.length; i++) {
                    s += item.params[i];
                }
                $("#assemblyView").append("<div class='asm-row'>" + s + "</div>");
                $("#lineNumber").append("<div class='asm-row'>" + (index + 1) + "</div>");
            });
            //添加断点点击事件
            $("#lineNumber").children("div").click(function () {
                let bp = $("#lineNumber").children("div").index(this);
                if ($(this).hasClass("breakpoint")) {
                    // 删除断点
                    breakpoints.splice(breakpoints.findIndex(item => item === bp), 1);
                    $(this).removeClass("breakpoint");
                } else {
                    //增加断电
                    breakpoints.push(bp);
                    $(this).addClass("breakpoint")
                }
            });
            break;
        case "return-execute":
            let status = data["data"];
            $("#storage").find(".card-body").html("");
            $("#memory").find(".card-body").html("");
            $("#stack").find(".card-body").html("");
            status["storage"].forEach(function (item) {
                $("#storage").find(".card-body").append(
                    "<div class='item'>" +
                    "<span class=\"key1\">" + item[0] + "</span> =>" +
                    "<div class=\"value\">" + item[1] + "</div>" +
                    "</div>"
                );
            });
            status["memory"].forEach(function (item) {
                $("#memory").find(".card-body").append(
                    "<div class='item'>" +
                    "<span class=\"key1\">" + item[0] + "</span> - <span class=\"key2\">" + item[1] + "</span>" +
                    "<div class=\"value\">" + item[2] + "</div>" +
                    "</div>"
                );
            });
            status["stack"].forEach(function (item) {
                $("#stack").find(".card-body").append(
                    "<div class='item'>" +
                    "<div class=\"value\">" + item + "</div>" +
                    "</div>"
                );
            });
            break;
        case "return-analyze":
            let vuls = data["data"];
            $("#vulnerabilities-container").html("");
            vuls.forEach(function (item) {
                let div = "";
                if (item["type"] === "timestamp_dependency") {
                    div += "<div class=\"vulnerability\">";
                    div += "<div class=\"vul-type\">Timestamp Dependency</div>";
                    div += "    <hr/>";
                    div += "    <div class=\"vul-info\">";
                    div += "        <div>Timestamp introduced at: <span>" + item["timestamp_address"] + "</span></div>";
                    div += "        <div>Dependency conditional jump: " + item["dependency_address"] + "</div>";
                    div += "    </div>";
                    div += "</div>";
                } else if (item["type"] === "unchecked_call") {
                    div += "<div class=\"vulnerability\">";
                    div += "<div class=\"vul-type\">Unchecked Call</div>";
                    div += "    <hr/>";
                    div += "    <div class=\"vul-info\">";
                    div += "        <div>Unchecked call at: " + item["call_address"] + "</div>";
                    div += "    </div>";
                    div += "</div>";
                } else if (item["type"] === "reentrancy") {
                    div += "<div class=\"vulnerability\">";
                    div += "<div class=\"vul-type\">Reentrancy</div>";
                    div += "    <hr/>";
                    div += "    <div class=\"vul-info\">";
                    div += "        <div>Vulnerable call at: <span>" + item["call_address"] + "</span></div>";
                    div += "        <div>Possible guard storage variable:</div>";
                    item["guard_storage_variables"].forEach(i => {
                        div += "    <div>" + i + "</div>";
                    });
                    div += "    </div>";
                    div += "</div>";
                }
                $("#vulnerabilities-container").append(div);
            });
    }
};

$("#compileBtn").click(function () {
    let sourceCode = $("#editor").val();
    let req = {
        "operation": "solc",
        "options": {
            "version": $("#version").val(),
            "optimization": $("#optimization").is(":checked"),
            "runtime": $("#runtime").is(":checked"),
        },
        "data": {
            "sourceCode": sourceCode,
        },
    };
    ws.send(JSON.stringify(req));
});

$("#debugBtn").click(function () {
    $("#compileBtn").trigger("click");
    $("#debuggerSection").trigger("click");
});

$("#analyzeBtn").click(function () {
    let req = {
        "operation": "analyze",
        "data": instructions,
    };
    ws.send(JSON.stringify(req));
});

$("#disasmBtn").click(function () {
    bytecode = $("#bytecode").val();
    let req = {
        "operation": "disasm",
        "data": {
            "bytecode": bytecode
        },
    };
    ws.send(JSON.stringify(req));
    breakpoints = [];
});

$("#startDebugBtn").click(function () {
    $("#debuggerSection").trigger("click");
    let req = {
        "operation": "debug",
        "type": "reset"
    };
    ws.send(JSON.stringify(req));
    highlight(0);
    debug_pointer = 0;
    $("#stepOverBtn").attr("disabled", false);
    $("#continueBtn").attr("disabled", false);
});

$("#continueBtn").click(function () {
    let req = {
        "operation": "debug",
        "type": "execute",
        "data": [instructions[debug_pointer]],
    };
    let p = instructions.length;
    for (let i = debug_pointer + 1; i < instructions.length; i++) {
        if (breakpoints.findIndex(item => item === i) !== -1) {
            //判断是否是断点
            p = i;
            break;
        }
        req["data"].push(instructions[i]);
    }
    ws.send(JSON.stringify(req));
    highlight(p);
    if (debug_pointer >= instructions.length) {
        $(this).attr("disabled", true);
        $("#stepOverBtn").attr("disabled", true);
    }
});

$("#stepOverBtn").click(function () {
    let req = {
        "operation": "debug",
        "type": "execute",
        "data": [instructions[debug_pointer]],
    };
    ws.send(JSON.stringify(req));
    highlight(debug_pointer + 1);
    if (debug_pointer >= instructions.length) {
        $(this).attr("disabled", true);
        $("#continueBtn").attr("disabled", true);
    }
});

function highlight(newIndex) {
    let assemblyView = $("#assemblyView");
    assemblyView.children("div").eq(debug_pointer).removeClass("asm-active");
    assemblyView.children("div").eq(newIndex).addClass("asm-active");
    debug_pointer = newIndex
}
