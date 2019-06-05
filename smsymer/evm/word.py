from smsymer.evm.fact import l_word


class Word(object):
    def __init__(self, data):
        if type(data) == int:
            # 转换成字节并增加前缀0x
            _data = hex(data)
        elif type(data) == str:
            _data = data
            # 增加前缀0x
            if not data.startswith('0x'):
                _data = '0x' + _data
        else:
            raise AttributeError
        self._byte32 = self._parse_byte_str(_data)

    @staticmethod
    def _parse_byte_str(byte_str):
        """
        :param byte_str: 十六进制字符串, e.g., 0x123456
        :return: l_word个字节组成的list, e.g., ['00', '00', '12', '34', '56']
        """
        if len(byte_str) > l_word * 2 + 2:
            # 长度超过l_word个字节则会被截断
            byte_str = '0x' + byte_str[2:][0 - l_word * 2:]
        byte32 = ['00'] * l_word
        byte = byte_str[2:]
        if len(byte) % 2 != 0:
            byte = '0' + byte
        for i in range(int(len(byte) / 2)):
            byte32[-1 - i] = byte[len(byte) - 2 * i - 2] + byte[len(byte) - 2 * i - 1]
        return byte32

    @property
    def byte_str(self):
        return '0x' + ''.join(self._byte32)

    def __hash__(self):
        return hash(int(self))

    def __str__(self):
        return self.byte_str

    def __int__(self):
        return int(self.byte_str, 16)

    def __hex__(self):
        return hex(int(self))

    def __oct__(self):
        return oct(int(self))

    def __index__(self):
        return int(self)

    def __getitem__(self, item):
        if type(item) == slice:
            return self._byte32[item.start:item.stop:item.step]
        else:
            return self._byte32[item]

    def is_neg(self):
        return int(self._byte32[0], 16) & 0x80 != 0

    def __neg__(self):
        # 取反加一
        if self == Word('80' + '00' * (l_word - 1)):
            raise ArithmeticError
        new_word = Word(self.byte_str)
        for ii in range(l_word):
            new_word._byte32[ii] = hex(int(new_word._byte32[ii], 16) ^ 0xFF)[2:]
        new_word._byte32 = new_word._parse_byte_str(hex(int(new_word.byte_str, 16) + 1))
        return new_word

    def __abs__(self):
        if int(self._byte32[0], 16) & 0x80 == 0:
            # 首位为0，正数
            return self
        else:
            # 首位为1，负数
            return -self

    def __add__(self, other):
        return Word(int(self) + int(other))

    def __sub__(self, other):
        return Word(int(self) - int(other))

    def __mul__(self, other):
        return Word(int(self) - int(other))

    def __floordiv__(self, other):
        """
        //重载为有符号除法
        :type other Word
        """
        if int(other) == 0:
            return Word(0)
        elif other == Word('FF' * l_word):
            return Word('FF' * l_word)
        else:
            r = abs(self) / abs(other)
            if self.is_neg() ^ other.is_neg():
                # 两者异号
                r = -r
            return r

    def __truediv__(self, other):
        # /重载为无符号除法
        if int(other) == 0:
            return Word(0)
        return Word(int(self) // int(other))

    def __mod__(self, other):
        if int(other) == 0:
            return Word(0)
        else:
            return Word(int(self) % int(other))

    def smod(self, other):
        """
        有符号模
        :type other Word
        """
        if int(other) == 0:
            return Word(0)
        else:
            r = abs(self) % abs(other)
            if self.is_neg():
                r = -r
            return r

    def __pow__(self, power, modulo=None):
        return Word(int(self) ** int(power))

    def sign_extend(self, t):
        r = int(self)
        mask = int('0' * t + '1' + '0' * (l_word * 8 - t - 1), 2)
        sign = int(r & mask != 0)
        mask = int(str(sign) * t + '0' * (l_word * 8 - t), 2)
        r = r | mask
        return Word(r)

    def __lt__(self, other):
        if int(self) < int(other):
            return 1
        else:
            return 0

    def __gt__(self, other):
        if int(self) > int(other):
            return 1
        else:
            return 0

    def slt(self, other):
        if self.is_neg():
            if not other.is_neg():
                return 1
            elif abs(self) > abs(other):
                return 1
            else:
                return 0
        elif other.is_neg():
            return 0
        elif abs(self) < abs(other):
            return 1
        else:
            return 0

    def sgt(self, other):
        if self.slt(other) and self == other:
            return 0
        else:
            return 1

    def __eq__(self, other):
        if int(other) == int(self):
            return 1
        else:
            return 0

    def is_zero(self):
        if int(self) == 0:
            return 1
        else:
            return 0

    def __and__(self, other):
        return Word(int(self) & int(other))

    def __or__(self, other):
        return Word(int(self) | int(other))

    def __xor__(self, other):
        return Word(int(self) ^ int(other))

    def __invert__(self):
        b = bin(int(self))[2:]
        b = '0' * (l_word * 8 - len(b)) + b
        b = ''.join(map(lambda bit: str(int(bit) ^ 1), b))
        return Word(int(b, 2))

    def retrieve_byte(self, index):
        # index count from left
        if index < 32:
            return Word(self._byte32[index])
        else:
            return Word(0)
