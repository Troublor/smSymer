class Memory(object):
    """
    自扩展的虚拟内存，字节寻址
    """

    def __init__(self):
        self._memory = []

    def _prepare_item(self, index):
        if len(self._memory) <= index:
            for i in range(index - len(self._memory) + 1):
                self._memory.append('00')

    def __getitem__(self, item):
        if type(item) == slice:
            s = []
            if item.step is None:
                for i in range(item.start, item.stop):
                    self._prepare_item(i)
                    s.append(self._memory[i])
            else:
                for i in range(item.start, item.stop, item.step):
                    self._prepare_item(i)
                    s.append(self._memory[i])
            return s
        else:
            if item < 0:
                raise AttributeError("Memory index can not be negative")
            self._prepare_item(item)
            return self._memory[item]

    def __setitem__(self, key, value):
        if key < 0:
            raise AttributeError("Memory index can not be negative")
        if type(value) == int:
            v = hex(value)[2:]
        elif type(value) == str:
            v = hex(int(value, 16))[2:]
        else:
            v = value
        # else:
        #     raise AttributeError("Invalid byte value: {0}".format(value))
        # if v > 0xff or v < 0:
        #     raise AttributeError("Invalid byte value: {0}".format(value))
        self._prepare_item(key)
        self._memory[key] = v