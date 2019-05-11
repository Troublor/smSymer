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

    def print(self, msg: Union[List[str], str]):
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
                    sys.stdout.write("{}\n".format(m))
                    sys.stdout.flush()
            else:
                sys.stdout.write("{}\n".format(msg))
                sys.stdout.flush()
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
                    sys.stderr.write("[ERROR] {}\n".format(msg))
                    sys.stderr.flush()
            else:
                sys.stderr.write("[ERROR] {}\n".format(error_msg))
                sys.stderr.flush()
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
                    sys.stdout.write("[INFO] {}\n".format(msg))
                    sys.stdout.flush()
            else:
                sys.stdout.write("[INFO] {}\n".format(info_msg))
                sys.stdout.flush()
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
                    sys.stderr.write("[WARN] {}\n".format(msg))
                    sys.stderr.flush()
            else:
                sys.stderr.write("[WARN] {}\n".format(warn_msg))
                sys.stderr.flush()
        else:
            raise AttributeError("Wrong printer type")
