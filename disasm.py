import os
import sys
from typing import List

from smsymer import Printer, utils
from smsymer.evm import ByteCode


def process(args):
    c_printer = Printer(type=Printer.CONSOLE)
    if args.result is not None:
        if not os.path.exists(args.result):
            c_printer.error("Result output directory '{0}' does not exist".format(args.result))
            sys.exit(-1)
        if not os.path.isdir(args.result):
            c_printer.error("'{0}' is not a directory".format(args.result))
            sys.exit(-1)
    if args.file:
        if args.source and args.extension is None:
            args.extension = 'sol'
        elif args.bytecode and args.extension is None:
            args.extension = 'hex'
        c_printer.info("processing files with extension '{0}'".format(args.extension))
        for s in args.input:
            if os.path.splitext(s)[-1][1:] != args.extension:
                c_printer.warn("file '{0}' extension mismatch".format(s))
                c_printer.warn("skipping '{0}'".format(s))
                continue
            if not os.path.exists(s):
                c_printer.error("file '{0}' does not exist".format(s))
                c_printer.warn("skipping '{0}'".format(s))
            elif not os.path.isfile(s):
                c_printer.error("'{0}' is not a file".format(s))
                c_printer.warn("skipping '{0}'".format(s))
            else:
                with open(s) as file:
                    c_printer.info("start disassembling {0}".format(s))
                    try:
                        if args.source:
                            bytecode = utils.compile_sol(s)
                        else:
                            bytecode = ''.join(file.readlines())
                        if args.result is not None:
                            filename = os.path.splitext(s)[0] + ".asm"
                            f_printer = Printer(type=Printer.FILE, filename=os.path.join(args.result, filename))
                            f_printer.print(disasm(bytecode))
                        else:
                            c_printer.print(disasm(bytecode))
                    except AttributeError as e:
                        c_printer.error(str(e))
                        c_printer.info("fail to disassemble {0}".format(s))
                    else:
                        c_printer.info("finish disassembling {0}".format(s))
    elif args.inline:
        for i, s in enumerate(args.input):
            bytecode = s
            c_printer.info("start disassembling {0}".format(s))
            try:
                if args.result is not None:
                    filename = str(i) + ".asm"
                    f_printer = Printer(type=Printer.FILE, filename=os.path.join(args.result, filename))
                    f_printer.print(disasm(bytecode))
                else:
                    c_printer.print(disasm(bytecode))
            except AttributeError as e:
                c_printer.error(str(e))
                c_printer.info("fail to disassemble {0}".format(s))
            else:
                c_printer.info("finish disassembling {0}".format(s))
    elif args.dir:
        if args.source and args.extension is None:
            args.extension = 'sol'
        elif args.bytecode and args.extension is None:
            args.extension = 'hex'
        c_printer.info("processing files with extension '{0}'".format(args.extension))
        for s in args.input:
            if not os.path.exists(s):
                c_printer.error("directory '{0}' does not exist")
                c_printer.warn("skipping '{0}'")
            elif not os.path.isdir(s):
                c_printer.error("'{0}' is not a directory")
                c_printer.warn("skipping '{0}'")
            else:
                process_dir(s, args)


def process_dir(directory: str, args):
    c_printer = Printer(Printer.CONSOLE)
    for item in os.listdir(directory):
        if os.path.isdir(item):
            if args.recursively:
                process_dir(item, args)
            else:
                c_printer.warn("not specify -R option, skipping subdirectory '{}'".format(item))
        else:
            if os.path.splitext(item)[-1][1:] != args.extension:
                c_printer.warn("file '{0}' extension mismatch".format(item))
                c_printer.warn("skipping '{0}'".format(item))
                continue
            with open(os.path.join(directory, item)) as file:
                c_printer.info("start disassembling {0}".format(os.path.join(directory, item)))
                try:
                    if args.source:
                        bytecode = utils.compile_sol(os.path.join(directory, item))
                    else:
                        bytecode = ''.join(file.readlines())
                    if args.result is not None:
                        filename = os.path.join(args.result, os.path.split(directory)[0], item + ".asm")
                        f_printer = Printer(Printer.FILE, filename=filename)
                        f_printer.print(disasm(bytecode))
                    else:
                        c_printer.print(disasm(bytecode))
                except AttributeError as e:
                    c_printer.error(str(e))
                    c_printer.info("fail to disassemble {0}".format(os.path.join(directory, item)))
                else:
                    c_printer.info("finish disassembling {0}".format(os.path.join(directory, item)))


def disasm(bytecode: str) -> List[str]:
    c_printer = Printer(Printer.CONSOLE)
    instructions = ByteCode.disasm(bytecode, c_printer)
    return list(map(lambda ins: str(ins), instructions))
