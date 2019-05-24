import os
import sys

from cprinter import CPrinter
from smsymer import Debugger
from smsymer.evm import ByteCode


def process(args):
    c_printer = CPrinter()
    if args.file:
        s = args.input
        if not os.path.exists(s):
            c_printer.error("file '{0}' does not exist".format(s))
        elif not os.path.isfile(s):
            c_printer.error("'{0}' is not a file".format(s))
        else:
            with open(s) as file:
                c_printer.info("start debugging {0}".format(s))
                try:
                    bytecode = ''.join(file.readlines())
                    instructions = ByteCode.disasm(bytecode, c_printer)
                    debugger = Debugger(instructions, c_printer)
                    debugger.start()
                except AttributeError as e:
                    c_printer.error(str(e))
                    c_printer.info("fail to debug {0}".format(s))
                else:
                    c_printer.info("finish debugging {0}".format(s))
    else:
        bytecode = args.input
        c_printer.info("start debugging")
        try:
            instructions = ByteCode.disasm(bytecode, c_printer)
            debugger = Debugger(instructions, c_printer)
            debugger.start()
        except AttributeError as e:
            c_printer.error(str(e))
            c_printer.info("fail to debug")
        else:
            c_printer.info("finish debugging")