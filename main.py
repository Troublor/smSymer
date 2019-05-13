import argparse
import sys

import debug
import disasm
import analyze

parser = argparse.ArgumentParser(description="SmSymer Smart Contract Analyzer")
parser.add_argument("-v", "-version", help="show the version of SmSymer", action="store_true")
sub_parser = parser.add_subparsers(help="commands", dest="command")

# disasm command
disasm_parser = sub_parser.add_parser("disasm", help="disassemble EVM bytecode")

disasm_group0 = disasm_parser.add_argument_group("specify the source of bytecode to disassemble")
disasm_group1 = disasm_group0.add_mutually_exclusive_group()
disasm_group1.add_argument("-f", "--file", help="disassemble the specified solidity source code file FILE",
                           action="store_true")
disasm_group1.add_argument("-d", "--dir", help="disassemble all files in directory DIR", action="store_true")
disasm_group1.add_argument("-l", "--inline", help="(default) disassemble source code specified in argument INLINE",
                           action="store_true", default=True)

disasm_group3 = disasm_parser.add_argument_group("type of source")
disasm_group4 = disasm_group3.add_mutually_exclusive_group()
disasm_group4.add_argument("-s", "--source", help="solidity source code", action="store_true")
disasm_group4.add_argument("-b", "--bytecode", help="(default) EVM bytecode", action="store_true", default=True)

disasm_group2 = disasm_parser.add_argument_group("specify where to output disassemble result")
disasm_group2.add_argument("-r", "--result", metavar="RESULT_DIR",
                           help="the output directory, if don't give this option,"
                                " the output will be printed in the console")

disasm_parser.add_argument("input", help="inline bytecode, file or directory used to disassemble", nargs='+')
disasm_parser.add_argument("-R", "--recursively",
                           help="recursively disassemble files all subdirectories (only valid when given -d option)",
                           action="store_true")
disasm_parser.add_argument("-e", "--extension",
                           help="file extension, only valid when -f or -d option is given. "
                                "(by default, 'sol' for source code file and 'hex' for bytecode file)",
                           default=None)

# analyze command
analyze_parser = sub_parser.add_parser("analyze", help="analyze smart contract")

analyze_group0 = analyze_parser.add_argument_group("specify the source of smart contract to analyze")
analyze_group1 = analyze_group0.add_mutually_exclusive_group()
analyze_group1.add_argument("-f", "--file", help="analyze the specified solidity source code file FILE",
                            action="store_true")
analyze_group1.add_argument("-d", "--dir", help="analyze all files in directory DIR", action="store_true")
analyze_group1.add_argument("-l", "--inline", help="(default) analyze source code specified in argument INLINE",
                            action="store_true", default=True)

analyze_group2 = analyze_parser.add_argument_group("type of source")
analyze_group3 = analyze_group2.add_mutually_exclusive_group()
analyze_group3.add_argument("-s", "--source", help="solidity source code", action="store_true")
analyze_group3.add_argument("-b", "--bytecode", help="(default) EVM bytecode", action="store_true", default=True)

analyze_group4 = analyze_parser.add_argument_group("specify where to output analysis result")
analyze_group4.add_argument("-r", "--result",
                            help="the output directory, if don't give this option,"
                                 " the output will be printed in the console")

analyze_parser.add_argument("-v", "--verbose", help="print the analysis log information", action="store_true")
analyze_parser.add_argument("--t-runtime", help="only analyze runtime code", action="store_true")
analyze_parser.add_argument("-R", "--recursively",
                            help="recursively disassemble files all subdirectories (only valid when given -d option)",
                            action="store_true")

analyze_parser.add_argument("input", help="inline smart contract, file or directory used to analyze", nargs='+')
analyze_parser.add_argument("-e", "--extension",
                            help="file extension, only valid when -f or -d option is given. "
                                 "(by default, 'sol' for source code file and 'hex' for bytecode file)",
                            default=None)

# debug command
debug_parser = sub_parser.add_parser("debug", help="debug EVM bytecode")

debug_group0 = debug_parser.add_argument_group("specify the source of bytecode to debug")
debug_group1 = debug_group0.add_mutually_exclusive_group()
debug_group1.add_argument("-f", "--file", help="debug the specified bytecode file FILE",
                          action="store_true")
debug_group1.add_argument("-l", "--inline", help="(default) debug bytecode specified in argument INLINE",
                          action="store_true", default=True)

debug_parser.add_argument("input", help="bytecode to debug")

args = parser.parse_args()

# process disasm sub-command
try:
    if args.command == "disasm":
        disasm.process(args)
    elif args.command == "analyze":
        analyze.process(args)
    elif args.command == "debug":
        debug.process(args)
    else:
        parser.print_help()
except AttributeError:
    sys.stderr.write("error: invalid command '{}'\n".format(' '.join(sys.argv)))
    parser.print_help()
