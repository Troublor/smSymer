from smsymer.analyzer.tool import RefTracker


class ImmutableStorageTracker(RefTracker):
    # track the storage variable and see if it is used in the path condition of a CALL operation.
    def __init__(self, addr: int, height: int, storage_addr, storage_value):
        super().__init__(addr, height)
        self.storage_addr = storage_addr
        self.storage_value = storage_value
        self.new_born = True

    def contains(self, h: int) -> bool:
        """
        判断给定栈中某一个高度h的值是否是当前对象的一个reference
        :param h:
        :return:
        """
        return h in self.h_list
