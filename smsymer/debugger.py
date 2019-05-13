from typing import List, Union, Tuple

from smsymer import Printer, utils
from smsymer.evm import Instruction, EVM


class Debugger(object):
    def __init__(self, instructions: List[Instruction]):
        self.instructions = instructions
        self._evm = EVM()
        self._pc = 0
        self._c_printer = Printer(Printer.CONSOLE)

    def help(self):
        self._c_printer.print("Debugger Usage:")
        self._c_printer.print()
        self._c_printer.print("Step Over:")
        self._c_printer.print("execute several steps and show the evm status")
        self._c_printer.print("\tcommand: s[n]")
        self._c_printer.print("\tn denotes the number steps")
        self._c_printer.print("\texamples: s, s1, s5")
        self._c_printer.print()
        self._c_printer.print("Resume Execution")
        self._c_printer.print("continue running until breakpoint")
        self._c_printer.print("\tcommand: r")
        self._c_printer.print()
        self._c_printer.print("Show Current EVM Status")
        self._c_printer.print("\tcommand: m")
        self._c_printer.print()
        self._c_printer.print("Show Instructions")
        self._c_printer.print("show instruction around the instruction that is about to execute now")
        self._c_printer.print("\tcommand: i[n]")
        self._c_printer.print("\tn denotes the range of instructions you want to show")
        self._c_printer.print("\texample: i3 will show the 3 instructions before the current instruction"
                              " and 3 instructions after the current instruction")
        self._c_printer.print()
        self._c_printer.print("Show Help Information")
        self._c_printer.print("\tcommand: h")
        self._c_printer.print()
        self._c_printer.print("Exit Debugger")
        self._c_printer.print("\tcommand: e")

    def start(self):
        self._reset()
        while True:
            command = input("debug:> ").strip()
            if command.startswith("h"):
                self.help()
            elif command.startswith("s"):
                if len(command) < 2 or not command[1].isdigit():
                    end = self.step_over()
                else:
                    end = self.step_over(int(command[1]))
                if end:
                    break
            elif command.startswith("r"):
                end = self.run_until_breakpoint()
                if end:
                    break
            elif command.startswith("m"):
                self.show_current_status()
            elif command.startswith("i"):
                if len(command) < 2 or not command[1].isdigit():
                    self.show_instructions()
                else:
                    self.show_instructions(int(command[1]))
            elif command.startswith("e"):
                break

    def _reset(self):
        self._pc = 0

    def _show_status(self):
        if len(self._evm.get_storage()) > 0:
            self._c_printer.print("Storage: ")
            for key, value in self._evm.get_storage().items():
                self._c_printer.print("\t{0} => {1}".format(key, value))
            self._c_printer.print()
        if len(self._evm.get_memory()) > 0:
            self._c_printer.print("Memory: ")
            for value in self._evm.get_memory().values():
                self._c_printer.print(
                    "\t{0}...{1} => {2}".format(value.start, value.start + value.length, value.content))
            self._c_printer.print()
        self._c_printer.print("Stack: ")
        for item in reversed(self._evm.get_stack()):
            if utils.is_symbol(item):
                self._c_printer.print("\t" + str(item))
            else:
                self._c_printer.print("\t" + hex(int(item))[2:].rjust(64, '0'))
        self._c_printer.print()

    def _get_next(self) -> Tuple[Union[Instruction, None], bool, bool]:
        """
        :return: instruction, whether next instruction is break point, whether there is no more instructions
        """
        if self._pc >= len(self.instructions):
            return None, False, True
        ins = self.instructions[self._pc]
        self._pc += 1
        if self._pc >= len(self.instructions):
            return ins, False, True
        _next = self.instructions[self._pc]
        is_break_point = False
        while _next.bytecode == 0xbb:
            is_break_point = True
            self._pc += 1
            if self._pc >= len(self.instructions):
                return ins, True, True
            _next = self.instructions[self._pc]
        return ins, is_break_point, False

    def step_over(self, n=1) -> bool:
        """
        run n steps
        :param n: number of steps to execute
        :return: whether program has finished
        """
        for i in range(n):
            ins, break_point, end = self._get_next()
            self._evm.exe(ins)
            self._c_printer.info("execute: {0}".format(ins))
            if end:
                self._show_status()
                return True
        self._show_status()
        self._c_printer.info("next: {0}".format(self.instructions[self._pc]))
        return False

    def run_until_breakpoint(self) -> bool:
        """
        run the program until break point
        :return: whether program has finished
        """
        ins, break_point, end = self._get_next()
        self._evm.exe(ins)
        self._c_printer.info("execute: {0}".format(ins))
        if end:
            self._show_status()
            return True
        while break_point is False:
            ins, break_point, end = self._get_next()
            self._evm.exe(ins)
            self._c_printer.info("execute: {0}".format(ins))
            if end:
                self._show_status()
                return True
        self._show_status()
        return False

    def show_current_status(self):
        self._show_status()
        self._c_printer.info("next: {0}".format(self.instructions[self._pc]))

    def show_instructions(self, n=1):
        for i in range(self._pc - n, self._pc + n + 1):
            if 0 <= i < len(self.instructions):
                if i == self._pc:
                    self._c_printer.green_print(str(self.instructions[i]))
                else:
                    self._c_printer.print(str(self.instructions[i]))
