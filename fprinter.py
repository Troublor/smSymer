import os
from typing import Union, List

from smsymer import Printer


class FPrinter(Printer):
    def __init__(self, filename):
        super().__init__()
        self.filename = filename
        if self.filename is not None:
            directory = os.path.split(filename)[0]
            if directory != '' and not os.path.exists(directory):
                os.mkdir(directory)

    def print(self, msg: Union[List[str], str] = ""):
        with open(self.filename, 'a') as file:
            if type(msg) is list:
                for m in msg:
                    file.write("{}\n".format(m))
            else:
                file.write("{}\n".format(msg))

    def error(self, error_msg: Union[List[str], str]):
        with open(self.filename, 'a') as file:
            if type(error_msg) is list:
                for msg in error_msg:
                    file.write("[ERROR] {}\n".format(msg))
            else:
                file.write("[ERROR] {}\n".format(error_msg))

    def info(self, info_msg: Union[List[str], str]):

        with open(self.filename, 'a') as file:
            if type(info_msg) is list:
                for msg in info_msg:
                    file.write("[INFO] {}\n".format(msg))
            else:
                file.write("[INFO] {}\n".format(info_msg))

    def warn(self, warn_msg: Union[List[str], str]):

        with open(self.filename, 'a') as file:
            if type(warn_msg) is list:
                for msg in warn_msg:
                    file.write("[WARN] {}\n".format(msg))
            else:
                file.write("[WARN] {}\n".format(warn_msg))
