from typing import Union, List

from smsymer import Printer


class CPrinter(Printer):
    def print(self, msg: Union[List[str], str] = ""):
        if type(msg) is list:
            for m in msg:
                print("{}".format(m))
        else:
            print("{}".format(msg))

    def error(self, error_msg: Union[List[str], str]):

        if type(error_msg) is list:
            for msg in error_msg:
                Printer.red_print("[ERROR] {}".format(msg))
        else:
            Printer.red_print("[ERROR] {}".format(error_msg))

    def info(self, info_msg: Union[List[str], str]):
        if type(info_msg) is list:
            for msg in info_msg:
                print("[INFO] {}".format(msg))
        else:
            print("[INFO] {}".format(info_msg))

    def warn(self, warn_msg: Union[List[str], str]):
        if type(warn_msg) is list:
            for msg in warn_msg:
                Printer.red_print("[WARN] {}".format(msg))
        else:
            Printer.red_print("[WARN] {}".format(warn_msg))
