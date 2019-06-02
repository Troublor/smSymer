import functools
import os
import sys
import uuid
from threading import Thread
from typing import List, Tuple, Dict
import timeout_decorator

from cprinter import CPrinter
from fprinter import FPrinter
from smsymer import utils, Printer
from smsymer.analyzer import Analyzer
from smsymer.analyzer.exception import AnalyzerException
from smsymer.cfg import CFG
from smsymer.evm import ByteCode


class TimeoutException(Exception):
    pass


def timeout(timeout):
    def deco(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            res = [TimeoutException('function [%s] timeout [%s seconds] exceeded!' % (func.__name__, timeout))]

            def newFunc():
                try:
                    res[0] = func(*args, **kwargs)
                except Exception as e:
                    res[0] = e

            t = Thread(target=newFunc)
            t.daemon = True
            try:
                t.start()
                t.join(timeout)
            except Exception as je:
                print('error starting thread')
                raise je
            ret = res[0]
            if isinstance(ret, BaseException):
                raise ret
            return ret

        return wrapper

    return deco


class CfgReport(object):
    def __init__(self):
        self.n_timestamp_dependency = 0
        self.n_unchecked_call = 0
        self.n_reentrancy = 0


class ContractReport(object):
    def __init__(self):
        self.cfg_reports: List[CfgReport] = []
        self.success = False

    def add(self, cfg_r: CfgReport):
        self.cfg_reports.append(cfg_r)
        self.success = True


class FileReport(object):
    def __init__(self):
        self.c_reports: List[ContractReport] = []
        self.success = False

    def add(self, c_r: ContractReport):
        self.c_reports.append(c_r)
        self.success = True


class Report(object):
    def __init__(self):
        self.f_reports: List[FileReport] = []

    def add(self, f_r: FileReport):
        self.f_reports.append(f_r)


def process(args):
    c_printer = CPrinter()
    result = {}
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
            f_r = FileReport()
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
                            bytecodes = utils.compile_sol(s, args.t_runtime)
                        else:
                            bytecodes = ''.join(file.readlines())

                        for bytecode in bytecodes:
                            if args.result is not None:
                                filename = os.path.splitext(s)[0] + ".txt"
                                f_printer = FPrinter(filename=os.path.join(args.result, filename))
                                c_r = analyze(bytecode, f_printer)
                            else:
                                c_r = analyze(bytecode, c_printer)
                            f_r.add(c_r)
                    except AttributeError as e:
                        c_printer.error(str(e))
                        c_printer.warn("fail to analyze {0}".format(s))
                    except AnalyzerException as e:
                        c_printer.warn("Unsupported feature: {}".format(e))
                        c_printer.warn("fail to analyze {0}".format(s))
                    except TimeoutException:
                        c_printer.warn("Analyze timeout")
                        c_printer.warn("fail to analyze {0}".format(s))
                    except Exception as e:
                        c_printer.error("SmSymer internal Error: {}".format(e))
                        c_printer.warn("fail to analyze {0}".format(s))
                    else:
                        c_printer.info("finish analyzing {0}".format(s))
            result[s] = f_r
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
                f_r = process_dir(s, args)
                result.update(f_r)
    else:
        for i, s in enumerate(args.input):
            bytecode = s
            c_printer.info("start analyzing {0}".format(s))
            f_r = FileReport()
            try:
                if args.result is not None:
                    filename = str(i) + ".txt"
                    f_printer = FPrinter(filename=os.path.join(args.result, filename))
                    c_r = analyze(bytecode, f_printer)
                else:
                    c_r = analyze(bytecode, c_printer)
                f_r.add(c_r)
            except AttributeError as e:
                c_printer.error(str(e))
                c_printer.warn("fail to analyze {0}".format(s))
            except AnalyzerException as e:
                c_printer.warn("Unsupported feature: {}".format(e))
                c_printer.warn("fail to analyze {0}".format(s))
            except TimeoutException:
                c_printer.warn("Analyze timeout")
                c_printer.warn("fail to analyze {0}".format(s))
            except Exception as e:
                c_printer.error("SmSymer internal Error: {}".format(e))
                c_printer.warn("fail to analyze {0}".format(s))
            else:
                c_printer.info("finish analyzing {0}".format(s))
            result[i] = f_r
    c_printer.info("***********************************")
    f_total = 0
    f_success = 0
    c_total = 0
    c_success = 0
    n_td = 0
    n_uc = 0
    n_r = 0
    for f_r in result.values():
        f_total += 1
        if f_r.success:
            f_success += 1
        for c_r in f_r.c_reports:
            c_total += 1
            if c_r.success:
                c_success += 1
            for cfg_r in c_r.cfg_reports:
                if cfg_r.n_timestamp_dependency > 0:
                    n_td += 1
                    break
            for cfg_r in c_r.cfg_reports:
                if cfg_r.n_unchecked_call > 0:
                    n_uc += 1
                    break
            for cfg_r in c_r.cfg_reports:
                if cfg_r.n_reentrancy > 0:
                    n_r += 1
                    break
    c_printer.info("SmSymer analyzed {0} files".format(f_total))
    c_printer.info("{0} success files, containing {0} contracts".format(f_success, c_total))
    c_printer.info("{0} success analyzed contracts".format(c_success))
    c_printer.info("{0} contracts contains Timestamp Dependency Vulnerability".format(n_td))
    c_printer.info("{0} contracts contains Unchecked Call Vulnerability".format(n_uc))
    c_printer.info("{0} contracts contains Reentrancy Vulnerability".format(n_r))

    # result_file = "C:\\Users\\troub\\Desktop\\result\\" + os.path.split(args.input[0])[-1]
    #
    # result_printer = FPrinter(result_file)
    # result_printer.info("{0} files".format(f_total))
    # result_printer.info("{0} success analyzed files".format(f_success))
    # result_printer.info("{0} contracts".format(c_total))
    # result_printer.info("{0} success analyzed contracts".format(c_success))
    # result_printer.info("{0} contracts contains Timestamp Dependency Vulnerability".format(n_td))
    # result_printer.info("{0} contracts contains Unchecked Call Vulnerability".format(n_uc))
    # result_printer.info("{0} contracts contains Reentrancy Vulnerability".format(n_r))


def process_dir(directory: str, args) -> Dict[str, FileReport]:
    result = {}
    c_printer = CPrinter()
    for item in os.listdir(directory):
        f_r: FileReport = FileReport()
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
                        bytecodes = utils.compile_sol(os.path.join(directory, item), args.t_runtime)
                    else:
                        bytecodes = ''.join(file.readlines())
                    for bytecode in bytecodes:
                        if args.result is not None:
                            filename = os.path.join(args.result, os.path.split(directory)[0], item + ".txt")
                            f_printer = FPrinter(filename=filename)
                            c_r = analyze(bytecode, f_printer)
                            f_r.add(c_r)
                        else:
                            c_r = analyze(bytecode, c_printer)
                            f_r.add(c_r)
                except AttributeError as e:
                    c_printer.error(str(e))
                    c_printer.warn("fail to analyze {0}".format(os.path.join(directory, item)))
                except AnalyzerException as e:
                    c_printer.warn("Unsupported feature: {}".format(e))
                    c_printer.warn("fail to analyze {0}".format(os.path.join(directory, item)))
                except TimeoutException:
                    c_printer.warn("Analyze timeout")
                    c_printer.warn("fail to analyze {0}".format(os.path.join(directory, item)))
                except Exception as e:
                    c_printer.error("SmSymer internal Error: {}".format(e))
                    c_printer.warn("fail to analyze {0}".format(os.path.join(directory, item)))
                else:
                    c_printer.info("finish analyzing {0}".format(os.path.join(directory, item)))
        result[os.path.join(directory, item)] = f_r
    return result


@timeout(300)
def analyze(bytecode: str, result_printer: Printer, verbose=False) -> ContractReport:
    result = ContractReport()
    c_printer = CPrinter()
    instructions = ByteCode.disasm(bytecode, c_printer)

    analyzer = Analyzer(instructions, result_printer, verbose)
    # analyze construction code
    result_printer.info("Checking construction assemble code")
    cfg_r = analyze_cfg(analyzer.construct_cfg, result_printer)
    result.add(cfg_r)
    result_printer.info("Checking construction assemble code...done")
    result_printer.info("===================================================")
    # analyze body code
    result_printer.info("Checking runtime assemble code")
    cfg_r = analyze_cfg(analyzer.body_cfg, result_printer, verbose)
    result.add(cfg_r)
    result_printer.info("Checking runtime assemble code...done")
    return result


def analyze_cfg(cfg: CFG, result_printer: Printer, verbose=False) -> CfgReport:
    result = CfgReport()
    if verbose:
        result_printer.info("assemble code begin")
        for ins in cfg.instructions:
            result_printer.print(str(ins))
        result_printer.info("assemble code end")

    timestamp_dependency_report = cfg.check_timestamp_dependency()
    if timestamp_dependency_report["vulnerable"]:
        result_printer.warn("found timestamp dependency")
        result_printer.warn("---------------------------------------------------")
        result.n_timestamp_dependency = len(timestamp_dependency_report["spots"])
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
        result.n_unchecked_call = len(uncheck_call_report["spots"])
        for index, report in enumerate(uncheck_call_report["spots"]):
            result_printer.warn("\t UNCHECKED CALL {0}".format(index))
            result_printer.warn("\t \t  unchecked call at {0}".format(
                cfg.get_instruction(report["call_address"])))
            result_printer.warn("---------------------------------------------------")

    reentrancy_report = cfg.check_reentrancy()
    if reentrancy_report["vulnerable"]:
        result_printer.warn("found reentrancy vulnerability")
        result_printer.warn("---------------------------------------------------")
        result.n_reentrancy = len(reentrancy_report["spots"])
        for index, report in enumerate(reentrancy_report["spots"]):
            result_printer.warn("\t REENTRANCY {0}".format(index))
            result_printer.warn("\t \t  reentrancy call at {0}".format(
                cfg.get_instruction(report["call_address"])))
            if len(report["storage_addresses"]) > 0:
                result_printer.warn("\t \t  possible guard storage variable")
            for addr in report["storage_addresses"]:
                result_printer.warn("\t \t  \tstorage variable loaded at {0}".format(cfg.get_instruction(addr)))
            result_printer.warn("---------------------------------------------------")
    return result
