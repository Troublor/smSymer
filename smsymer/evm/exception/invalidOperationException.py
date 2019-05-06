class InvalidOperationException(Exception):
    def __init__(self, byte):
        self.byte = byte

    def __str__(self):
        return "Invalid bytecode: {0}".format(self.byte)