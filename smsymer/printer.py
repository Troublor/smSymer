import os
import sys
from typing import Union, List


class Printer(object):
    FILE = 1
    CONSOLE = 2

    def __init__(self, type=FILE, filename=None):
        self.type = type
        self.filename = filename
        if self.filename is not None:
            directory = os.path.split(filename)[0]
            if directory != '' and not os.path.exists(directory):
                os.mkdir(directory)

    def print(self, msg: Union[List[str], str] = ""):
        if self.type == Printer.FILE:
            with open(self.filename, 'a') as file:
                if type(msg) is list:
                    for m in msg:
                        file.write("{}\n".format(m))
                else:
                    file.write("{}\n".format(msg))
        elif self.type == Printer.CONSOLE:
            if type(msg) is list:
                for m in msg:
                    print("{}".format(m))
            else:
                print("{}".format(msg))
        else:
            raise AttributeError("Wrong printer type")

    def error(self, error_msg: Union[List[str], str]):
        if self.type == Printer.FILE:
            with open(self.filename, 'a') as file:
                if type(error_msg) is list:
                    for msg in error_msg:
                        file.write("[ERROR] {}\n".format(msg))
                else:
                    file.write("[ERROR] {}\n".format(error_msg))
        elif self.type == Printer.CONSOLE:
            if type(error_msg) is list:
                for msg in error_msg:
                    Printer.red_print("[ERROR] {}".format(msg))
            else:
                Printer.red_print("[ERROR] {}".format(error_msg))
        else:
            raise AttributeError("Wrong printer type")

    def info(self, info_msg: Union[List[str], str]):
        if self.type == Printer.FILE:
            with open(self.filename, 'a') as file:
                if type(info_msg) is list:
                    for msg in info_msg:
                        file.write("[INFO] {}\n".format(msg))
                else:
                    file.write("[INFO] {}\n".format(info_msg))
        elif self.type == Printer.CONSOLE:
            if type(info_msg) is list:
                for msg in info_msg:
                    print("[INFO] {}".format(msg))
            else:
                print("[INFO] {}".format(info_msg))
        else:
            raise AttributeError("Wrong printer type")

    def warn(self, warn_msg: Union[List[str], str]):
        if self.type == Printer.FILE:
            with open(self.filename, 'a') as file:
                if type(warn_msg) is list:
                    for msg in warn_msg:
                        file.write("[WARN] {}\n".format(msg))
                else:
                    file.write("[WARN] {}\n".format(warn_msg))
        elif self.type == Printer.CONSOLE:
            if type(warn_msg) is list:
                for msg in warn_msg:
                    Printer.red_print("[WARN] {}".format(msg))
            else:
                Printer.red_print("[WARN] {}".format(warn_msg))
        else:
            raise AttributeError("Wrong printer type")

    @staticmethod
    def red_print(msg: str):
        print("\033[0;31;m{0}\033[0m".format(msg))

    @staticmethod
    def green_print(msg: str):
        print("\033[0;32;m{0}\033[0m".format(msg))
