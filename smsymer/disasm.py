import os
import sys

from smsymer import Printer
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
        for s in args.source:
            if not os.path.exists(s):
                c_printer.error("file '{0}' does not exist".format(s))
                c_printer.warn("skipping '{0}'".format(s))
            elif not os.path.isfile(s):
                c_printer.error("'{0}' is not a file".format(s))
                c_printer.warn("skipping '{0}'".format(s))
            else:
                with open(s) as file:
                    bytecode = ''.join(file.readlines())
                    c_printer.info("start disassembling {0}".format(s))
                    if args.result is not None:
                        filename = os.path.splitext(s)[0] + ".asm"
                        f_printer = Printer(type=Printer.FILE, filename=os.path.join(args.result, filename))
                        f_printer.print("{0}".format(disasm(bytecode)))
                    else:
                        c_printer.print("{0}".format(disasm(bytecode)))
                    c_printer.info("finish disassembling {0}".format(s))
    elif args.inline:
        for i, s in enumerate(args.source):
            bytecode = s
            c_printer.info("start disassembling {0}".format(s))
            if args.result is not None:
                filename = str(i) + ".asm"
                f_printer = Printer(type=Printer.FILE, filename=os.path.join(args.result, filename))
                f_printer.print("{0}".format(disasm(bytecode)))
            else:
                c_printer.print("{0}".format(disasm(bytecode)))
            c_printer.info("finish disassembling {0}".format(s))
    elif args.dir:
        for s in args.source:
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
            with open(os.path.join(directory, item)) as file:
                bytecode = ''.join(file.readlines())
                c_printer.info("start disassembling {0}".format(os.path.join(directory, item)))
                if args.result is not None:
                    filename = os.path.join(args.result, os.path.split(directory)[0], item + ".asm")
                    f_printer = Printer(Printer.FILE, filename=filename)
                    f_printer.print("{0}".format(disasm(bytecode)))
                else:
                    c_printer.print("{0}".format(disasm(bytecode)))
                c_printer.info("finish disassembling {0}".format(os.path.join(directory, item)))


def disasm(bytecode: str) -> str:
    instructions = ByteCode.disasm(bytecode)
