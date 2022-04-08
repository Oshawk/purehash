from __future__ import annotations

from purehash._common import Hash
from purehash._util import left_rotate, pack, padding, unpack


class SHA1(Hash):
    _a: int
    _b: int
    _c: int
    _d: int
    _e: int

    def __init__(self, message: bytes = b""):
        self._a = 0x67452301
        self._b = 0xEFCDAB89
        self._c = 0x98BADCFE
        self._d = 0x10325476
        self._e = 0xC3D2E1F0

        super().__init__(message=message)

    def _process_block(self, block: bytes) -> None:
        w: list[int] = list(unpack(4, False, block))

        for i in range(16, 80):
            w.append(left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1, 32))

        a: int = self._a
        b: int = self._b
        c: int = self._c
        d: int = self._d
        e: int = self._e

        f: int
        k: int
        temp: int
        for i in range(80):
            if i < 20:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (left_rotate(a, 5, 32) + f + e + k + w[i]) % (2**32)
            e = d
            d = c
            c = left_rotate(b, 30, 32)
            b = a
            a = temp

        self._a = (self._a + a) % (2**32)
        self._b = (self._b + b) % (2**32)
        self._c = (self._c + c) % (2**32)
        self._d = (self._d + d) % (2**32)
        self._e = (self._e + e) % (2**32)

    def update(self, message: bytes) -> None:
        self._buffer += message

        for _ in range(len(self._buffer) // 64):
            self._process_block(self._buffer[:64])

            self._blocks_processed += 1
            self._buffer = self._buffer[64:]

    def digest(self) -> bytes:
        # Save state.
        a: int = self._a
        b: int = self._b
        c: int = self._c
        d: int = self._d
        e: int = self._e

        buffer_length: int = len(self._buffer)
        self._buffer += padding(
            (self._blocks_processed * 64) + buffer_length, 64, 8, False
        )

        self._process_block(self._buffer[:64])

        if len(self._buffer) == 128:
            self._process_block(self._buffer[64:])

        result: bytes = pack(4, False, self._a, self._b, self._c, self._d, self._e)

        # Restore state.
        self._a = a
        self._b = b
        self._c = c
        self._d = d
        self._e = e

        # Restore buffer.
        self._buffer = self._buffer[:buffer_length]

        return result
