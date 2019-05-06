from typing import Union

from .word import Word


class Stack(object):
    def __init__(self):
        # list 尾部为栈顶
        self._stack = []

    def __len__(self):
        return len(self._stack)

    def __getitem__(self, item):
        return self._stack[item]

    def push(self, operand: Word):
        self._stack.append(operand)

    def pop(self) -> Union[Word, None]:
        if len(self._stack) < 1:
            return None
        out = self._stack[-1]
        self._stack = self._stack[:-1]
        return out

    def dup(self, index: int):
        item = self._stack[-index]
        self.push(item)

    def swap(self, index: int):
        item = self.pop()
        self.dup(index)
        self._stack[-index - 1] = item
