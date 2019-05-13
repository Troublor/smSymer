from z3 import Int

from smsymer import utils


class MemoryItem(object):
    def __init__(self, start, length, content):
        self.start = start
        self.length = length
        self.content = content

    def conflicts_with(self, other):
        # if self will modify the content of other
        if utils.is_symbol(self.start) or utils.is_symbol(self.length) or utils.is_symbol(
                other.start) or utils.is_symbol(other.length):
            return False
        if self.start <= other.start < self.start + self.length or other.start <= self.start < other.start + other.length:
            return True
        else:
            return False


class HashMemory(object):
    def __init__(self):
        self._memory = {}
        # self.Ui = 0

    def load(self, start, length):
        if start not in self._memory.keys():
            return Int("M_{0}_{1}".format(start, length))
        tmp: MemoryItem = self._memory[start]
        if tmp.length == length:
            return tmp.content
        return Int("M_{0}_{1}".format(start, length))

    def store(self, start, length, content):
        tmp = MemoryItem(start, length, content)
        for addr, item in self._memory.copy().items():
            if tmp.conflicts_with(item):
                del self._memory[addr]
        self._memory[start] = tmp

    def get_memory(self):
        return self._memory
