import asyncio
import json
from typing import Union, List

from smsymer import Printer


class WPrinter(Printer):
    def __init__(self, websocket, identifier: str = ""):
        super().__init__()
        self.websocket = websocket
        self.identifier = identifier
        self.loop = asyncio.get_event_loop()

    def print(self, msg: Union[List[str], str] = ""):
        resp = {
            "operation": "log",
            "type": "normal",
            "data": "",
            "identifier": self.identifier,
        }
        if type(msg) is List:
            for m in msg:
                resp["data"] = m
                self.loop.create_task(self.websocket.send(json.dumps(resp)))
        else:
            resp["data"] = msg
            self.loop.create_task(self.websocket.send(json.dumps(resp)))

    def error(self, error_msg: Union[List[str], str]):
        resp = {
            "operation": "log",
            "type": "error",
            "data": "",
            "identifier": self.identifier,
        }
        if type(error_msg) is List:
            for m in error_msg:
                resp["data"] = m
                self.loop.create_task(self.websocket.send(json.dumps(resp)))
        else:
            resp["data"] = error_msg
            self.loop.create_task(self.websocket.send(json.dumps(resp)))

    def info(self, info_msg: Union[List[str], str]):
        resp = {
            "operation": "log",
            "type": "info",
            "data": "",
            "identifier": self.identifier,
        }
        if type(info_msg) is List:
            for m in info_msg:
                resp["data"] = m
                self.loop.create_task(self.websocket.send(json.dumps(resp)))
        else:
            resp["data"] = info_msg
            self.loop.create_task(self.websocket.send(json.dumps(resp)))

    def warn(self, warn_msg: Union[List[str], str]):
        resp = {
            "operation": "log",
            "type": "warn",
            "data": "",
            "identifier": self.identifier,
        }
        if type(warn_msg) is List:
            for m in warn_msg:
                resp["data"] = m
                self.loop.create_task(self.websocket.send(json.dumps(resp)))
        else:
            resp["data"] = warn_msg
            self.loop.create_task(self.websocket.send(json.dumps(resp)))
