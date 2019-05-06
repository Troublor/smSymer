from smsymer.evm.fact import get_operation_name


class InsufficientInputException(Exception):
    def __init__(self, byte, got_amount, expected_amount):
        self.byte = byte
        self.got_amount = got_amount
        self.expected_amount = expected_amount

    def __str__(self):
        return "Insufficient Input for operation {0}({1}): expected_amount={2}, got_amount={3}".format(
            get_operation_name(self.byte), hex(self.byte), self.expected_amount, self.got_amount)
