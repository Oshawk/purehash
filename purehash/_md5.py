from struct import pack, unpack

from purehash._util import left_rotate

SHIFTS: tuple[int, ...] = (
    7,
    12,
    17,
    22,
    7,
    12,
    17,
    22,
    7,
    12,
    17,
    22,
    7,
    12,
    17,
    22,
    5,
    9,
    14,
    20,
    5,
    9,
    14,
    20,
    5,
    9,
    14,
    20,
    5,
    9,
    14,
    20,
    4,
    11,
    16,
    23,
    4,
    11,
    16,
    23,
    4,
    11,
    16,
    23,
    4,
    11,
    16,
    23,
    6,
    10,
    15,
    21,
    6,
    10,
    15,
    21,
    6,
    10,
    15,
    21,
    6,
    10,
    15,
    21,
)
SINES: tuple[int, ...] = (
    0xD76AA478,
    0xE8C7B756,
    0x242070DB,
    0xC1BDCEEE,
    0xF57C0FAF,
    0x4787C62A,
    0xA8304613,
    0xFD469501,
    0x698098D8,
    0x8B44F7AF,
    0xFFFF5BB1,
    0x895CD7BE,
    0x6B901122,
    0xFD987193,
    0xA679438E,
    0x49B40821,
    0xF61E2562,
    0xC040B340,
    0x265E5A51,
    0xE9B6C7AA,
    0xD62F105D,
    0x02441453,
    0xD8A1E681,
    0xE7D3FBC8,
    0x21E1CDE6,
    0xC33707D6,
    0xF4D50D87,
    0x455A14ED,
    0xA9E3E905,
    0xFCEFA3F8,
    0x676F02D9,
    0x8D2A4C8A,
    0xFFFA3942,
    0x8771F681,
    0x6D9D6122,
    0xFDE5380C,
    0xA4BEEA44,
    0x4BDECFA9,
    0xF6BB4B60,
    0xBEBFBC70,
    0x289B7EC6,
    0xEAA127FA,
    0xD4EF3085,
    0x04881D05,
    0xD9D4D039,
    0xE6DB99E5,
    0x1FA27CF8,
    0xC4AC5665,
    0xF4292244,
    0x432AFF97,
    0xAB9423A7,
    0xFC93A039,
    0x655B59C3,
    0x8F0CCC92,
    0xFFEFF47D,
    0x85845DD1,
    0x6FA87E4F,
    0xFE2CE6E0,
    0xA3014314,
    0x4E0811A1,
    0xF7537E82,
    0xBD3AF235,
    0x2AD7D2BB,
    0xEB86D391,
)


def padding(length: int) -> bytes:
    padding_: bytearray = bytearray(b"\x80")

    length_mod: int = length % 64
    if length_mod < 56:
        padding_ += b"\x00" * (55 - length_mod)
    else:
        padding_ += b"\x00" * (119 - length_mod)

    padding_ += pack("<Q", (length * 8) % (2**64))

    return bytes(padding_)


class MD5:
    a: int
    b: int
    c: int
    d: int

    blocks_processed: int
    buffer: bytearray

    def __init__(self, message: bytes = b""):
        self.a = 0x67452301
        self.b = 0xEFCDAB89
        self.c = 0x98BADCFE
        self.d = 0x10325476

        self.blocks_processed = 0
        self.buffer = bytearray()

        self.update(message)

    def _process_block(self, block: bytes):
        m: tuple[int, ...] = unpack("<IIIIIIIIIIIIIIII", block)

        a: int = self.a
        b: int = self.b
        c: int = self.c
        d: int = self.d

        f: int
        g: int
        for i in range(64):
            if i < 16:
                f = (b & c) | ((~b) & d)
                g = i
            elif i < 32:
                f = (d & b) | ((~d) & c)
                g = (5 * i + 1) % 16
            elif i < 48:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            else:
                f = c ^ (b | (~d))
                g = (7 * i) % 16

            f = (f + a + SINES[i] + m[g]) % (2**32)
            a = d
            d = c
            c = b
            b = b + left_rotate(f, SHIFTS[i], 32)

        self.a = (self.a + a) % (2**32)
        self.b = (self.b + b) % (2**32)
        self.c = (self.c + c) % (2**32)
        self.d = (self.d + d) % (2**32)

    def update(self, message) -> None:
        self.buffer += message

        for _ in range(len(self.buffer) // 64):
            self._process_block(self.buffer[:64])

            self.blocks_processed += 1
            self.buffer = self.buffer[64:]

    def digest(self) -> bytes:
        # Save state.
        a: int = self.a
        b: int = self.b
        c: int = self.c
        d: int = self.d

        buffer_length: int = len(self.buffer)
        self.buffer += padding((self.blocks_processed * 64) + buffer_length)

        self._process_block(self.buffer[:64])

        if len(self.buffer) == 128:
            self._process_block(self.buffer[64:])

        result: bytes = pack("<IIII", self.a, self.b, self.c, self.d)

        # Restore state.
        self.a = a
        self.b = b
        self.c = c
        self.d = d

        # Restore buffer.
        self.buffer = self.buffer[:buffer_length]

        return result

    def hexdigest(self) -> str:
        return self.digest().hex()
