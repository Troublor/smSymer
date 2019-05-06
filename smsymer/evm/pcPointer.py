class PcPointer(object):
    NEXT_ADDR = 0
    STOP = -1
    JUMP = 1
    JUMPI = 2

    def __init__(self, status, addr=None, cond=None):
        self.status = status
        self.addr = addr
        self.condition = cond
