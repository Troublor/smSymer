import os
import sys
from typing import List

from smsymer import Printer, utils
from smsymer.analyzer import Analyzer
from smsymer.cfg import CFG
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
                    c_printer.info("start analyzing {0}".format(s))
                    try:
                        if args.source:
                            bytecode = utils.compile_sol(s)
                        else:
                            bytecode = ''.join(file.readlines())
                        if args.result is not None:
                            filename = os.path.splitext(s)[0] + ".txt"
                            f_printer = Printer(type=Printer.FILE, filename=os.path.join(args.result, filename))
                            analyze(bytecode, f_printer)
                        else:
                            analyze(bytecode, c_printer)
                    except AttributeError as e:
                        c_printer.error(str(e))
                        c_printer.info("fail to analyze {0}".format(s))
                    else:
                        c_printer.info("finish analyzing {0}".format(s))
    elif args.inline:
        for i, s in enumerate(args.input):
            bytecode = s
            c_printer.info("start analyzing {0}".format(s))
            try:
                if args.result is not None:
                    filename = str(i) + ".txt"
                    f_printer = Printer(type=Printer.FILE, filename=os.path.join(args.result, filename))
                    analyze(bytecode, f_printer)
                else:
                    analyze(bytecode, c_printer)
            except AttributeError as e:
                c_printer.error(str(e))
                c_printer.info("fail to analyze {0}".format(s))
            else:
                c_printer.info("finish analyzing {0}".format(s))
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
                c_printer.info("start analyzing {0}".format(os.path.join(directory, item)))
                try:
                    if args.source:
                        bytecode = utils.compile_sol(os.path.join(directory, item))
                    else:
                        bytecode = ''.join(file.readlines())
                    if args.result is not None:
                        filename = os.path.join(args.result, os.path.split(directory)[0], item + ".txt")
                        f_printer = Printer(Printer.FILE, filename=filename)
                        analyze(bytecode, f_printer)
                    else:
                        analyze(bytecode, c_printer)
                except AttributeError as e:
                    c_printer.error(str(e))
                    c_printer.info("fail to analyze {0}".format(os.path.join(directory, item)))
                else:
                    c_printer.info("finish analyzing {0}".format(os.path.join(directory, item)))


def analyze(bytecode: str, result_printer: Printer, verbose=False):
    c_printer = Printer(Printer.CONSOLE)
    instructions = ByteCode.disasm(bytecode, c_printer)

    analyzer = Analyzer(instructions, result_printer, verbose)
    # analyze construction code
    result_printer.info("Checking construction assemble code")
    analyze_cfg(analyzer.construct_cfg, result_printer)
    result_printer.info("Checking construction assemble code...done")
    result_printer.info("===================================================")
    # analyze body code
    result_printer.info("Checking runtime assemble code")
    analyze_cfg(analyzer.body_cfg, result_printer, verbose)
    result_printer.info("Checking runtime assemble code...done")


def analyze_cfg(cfg: CFG, result_printer: Printer, verbose=False):
    if verbose:
        result_printer.info("assemble code begin")
        for ins in cfg.instructions:
            result_printer.print(str(ins))
        result_printer.info("assemble code end")

    timestamp_dependency_report = cfg.check_timestamp_dependency()
    if timestamp_dependency_report["vulnerable"]:
        result_printer.warn("found timestamp dependency")
        result_printer.warn("---------------------------------------------------")
        for index, report in enumerate(timestamp_dependency_report["spots"]):
            result_printer.warn("\t TIMESTAMP DEPENDENCY {0}".format(index))
            result_printer.warn("\t \t  timestamp introduced at {0}".format(
                cfg.get_instruction(report["timestamp_address"])))
            result_printer.warn("\t \t  used in path condition at {0}".format(
                cfg.get_instruction(report["dependency_address"])))
            result_printer.warn("---------------------------------------------------")

    uncheck_call_report = cfg.check_unchecked_call()
    if uncheck_call_report["vulnerable"]:
        result_printer.warn("found unchecked call")
        result_printer.warn("---------------------------------------------------")
        for index, report in enumerate(uncheck_call_report["spots"]):
            result_printer.warn("\t UNCHECKED CALL {0}".format(index))
            result_printer.warn("\t \t  unchecked call at {0}".format(
                cfg.get_instruction(report["call_address"])))
            result_printer.warn("---------------------------------------------------")

    reentrancy_report = cfg.check_reentrancy()
    if reentrancy_report["vulnerable"]:
        result_printer.warn("found reentrancy vulnerability")
        result_printer.warn("---------------------------------------------------")
        for index, report in enumerate(reentrancy_report["spots"]):
            result_printer.warn("\t REENTRANCY {0}".format(index))
            result_printer.warn("\t \t  reentrancy call at {0}".format(
                cfg.get_instruction(report["call_address"])))
            if len(report["storage_addresses"]) > 0:
                result_printer.warn("\t \t  possible guard storage variable")
            for addr in report["storage_addresses"]:
                result_printer.warn("\t \t  \tstorage variable loaded at {0}".format(cfg.get_instruction(addr)))
            result_printer.warn("---------------------------------------------------")
