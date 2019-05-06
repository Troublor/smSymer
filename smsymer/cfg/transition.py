from .block import Block


class Transition(object):
    """
    Transition from basic block0 to basic block1
    """

    def __init__(self, from_: Block, to_: Block, constrain):
        """
        Initialization function
        :param from_: Transition is from block0 to block1
        :param to_: Transition is from block0 to block1
        :param constrain: Z3 constrains, transition happens when constrains are satisfied
        """
        self.constrain = constrain
        self.from_ = from_
        self.to_ = to_

    def __str__(self):
        return "{0} -> {1}, {2}".format(hex(self.from_.address), hex(self.to_.address), self.constrain)
