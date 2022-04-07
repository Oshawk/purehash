from __future__ import annotations

from purehash._util import pack, padding, right_rotate, unpack

SHA256_CONSTANTS: tuple[int, ...] = (
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
)


class SHA256:
    _a: int
    _b: int
    _c: int
    _d: int
    _e: int
    _f: int
    _g: int
    _h: int

    _blocks_processed: int
    _buffer: bytearray

    def __init__(self, message: bytes = b"") -> None:
        self._a = 0x6A09E667
        self._b = 0xBB67AE85
        self._c = 0x3C6EF372
        self._d = 0xA54FF53A
        self._e = 0x510E527F
        self._f = 0x9B05688C
        self._g = 0x1F83D9AB
        self._h = 0x5BE0CD19

        self._blocks_processed = 0
        self._buffer = bytearray()

        self.update(message)

    def _process_block(self, block: bytes) -> None:
        w: list[int] = list(unpack(4, False, block))

        i: int
        s0: int
        s1: int
        for i in range(16, 64):
            s0 = (
                right_rotate(w[i - 15], 7, 32)
                ^ right_rotate(w[i - 15], 18, 32)
                ^ (w[i - 15] >> 3)
            )
            s1 = (
                right_rotate(w[i - 2], 17, 32)
                ^ right_rotate(w[i - 2], 19, 32)
                ^ (w[i - 2] >> 10)
            )
            w.append((w[i - 16] + s0 + w[i - 7] + s1) % (2**32))

        a: int = self._a
        b: int = self._b
        c: int = self._c
        d: int = self._d
        e: int = self._e
        f: int = self._f
        g: int = self._g
        h: int = self._h

        ch: int
        temp0: int
        maj: int
        temp1: int
        for i in range(64):
            s1 = (
                right_rotate(e, 6, 32)
                ^ right_rotate(e, 11, 32)
                ^ right_rotate(e, 25, 32)
            )
            ch = (e & f) ^ ((~e) & g)
            temp0 = (h + s1 + ch + SHA256_CONSTANTS[i] + w[i]) % (2**32)
            s0 = (
                right_rotate(a, 2, 32)
                ^ right_rotate(a, 13, 32)
                ^ right_rotate(a, 22, 32)
            )
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp1 = (s0 + maj) % (2**32)

            h = g
            g = f
            f = e
            e = (d + temp0) % (2**32)
            d = c
            c = b
            b = a
            a = (temp0 + temp1) % (2**32)

        self._a = (self._a + a) % (2**32)
        self._b = (self._b + b) % (2**32)
        self._c = (self._c + c) % (2**32)
        self._d = (self._d + d) % (2**32)
        self._e = (self._e + e) % (2**32)
        self._f = (self._f + f) % (2**32)
        self._g = (self._g + g) % (2**32)
        self._h = (self._h + h) % (2**32)

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
        f: int = self._f
        g: int = self._g
        h: int = self._h

        buffer_length: int = len(self._buffer)
        self._buffer += padding(
            (self._blocks_processed * 64) + buffer_length, 64, 8, False
        )

        self._process_block(self._buffer[:64])

        if len(self._buffer) == 128:
            self._process_block(self._buffer[64:])

        result: bytes = pack(
            4,
            False,
            self._a,
            self._b,
            self._c,
            self._d,
            self._e,
            self._f,
            self._g,
            self._h,
        )

        # Restore state.
        self._a = a
        self._b = b
        self._c = c
        self._d = d
        self._e = e
        self._f = f
        self._g = g
        self._h = h

        # Restore buffer.
        self._buffer = self._buffer[:buffer_length]

        return result

    def hexdigest(self) -> str:
        return self.digest().hex()


SHA512_CONSTANTS: tuple[int, ...] = (
    0x428A2F98D728AE22,
    0x7137449123EF65CD,
    0xB5C0FBCFEC4D3B2F,
    0xE9B5DBA58189DBBC,
    0x3956C25BF348B538,
    0x59F111F1B605D019,
    0x923F82A4AF194F9B,
    0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242,
    0x12835B0145706FBE,
    0x243185BE4EE4B28C,
    0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F,
    0x80DEB1FE3B1696B1,
    0x9BDC06A725C71235,
    0xC19BF174CF692694,
    0xE49B69C19EF14AD2,
    0xEFBE4786384F25E3,
    0x0FC19DC68B8CD5B5,
    0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275,
    0x4A7484AA6EA6E483,
    0x5CB0A9DCBD41FBD4,
    0x76F988DA831153B5,
    0x983E5152EE66DFAB,
    0xA831C66D2DB43210,
    0xB00327C898FB213F,
    0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2,
    0xD5A79147930AA725,
    0x06CA6351E003826F,
    0x142929670A0E6E70,
    0x27B70A8546D22FFC,
    0x2E1B21385C26C926,
    0x4D2C6DFC5AC42AED,
    0x53380D139D95B3DF,
    0x650A73548BAF63DE,
    0x766A0ABB3C77B2A8,
    0x81C2C92E47EDAEE6,
    0x92722C851482353B,
    0xA2BFE8A14CF10364,
    0xA81A664BBC423001,
    0xC24B8B70D0F89791,
    0xC76C51A30654BE30,
    0xD192E819D6EF5218,
    0xD69906245565A910,
    0xF40E35855771202A,
    0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8,
    0x1E376C085141AB53,
    0x2748774CDF8EEB99,
    0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63,
    0x4ED8AA4AE3418ACB,
    0x5B9CCA4F7763E373,
    0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC,
    0x78A5636F43172F60,
    0x84C87814A1F0AB72,
    0x8CC702081A6439EC,
    0x90BEFFFA23631E28,
    0xA4506CEBDE82BDE9,
    0xBEF9A3F7B2C67915,
    0xC67178F2E372532B,
    0xCA273ECEEA26619C,
    0xD186B8C721C0C207,
    0xEADA7DD6CDE0EB1E,
    0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA,
    0x0A637DC5A2C898A6,
    0x113F9804BEF90DAE,
    0x1B710B35131C471B,
    0x28DB77F523047D84,
    0x32CAAB7B40C72493,
    0x3C9EBE0A15C9BEBC,
    0x431D67C49C100D4C,
    0x4CC5D4BECB3E42B6,
    0x597F299CFC657E2A,
    0x5FCB6FAB3AD6FAEC,
    0x6C44198C4A475817,
)


class SHA512:
    _a: int
    _b: int
    _c: int
    _d: int
    _e: int
    _f: int
    _g: int
    _h: int

    _blocks_processed: int
    _buffer: bytearray

    def __init__(self, message: bytes = b"") -> None:
        self._a = 0x6A09E667F3BCC908
        self._b = 0xBB67AE8584CAA73B
        self._c = 0x3C6EF372FE94F82B
        self._d = 0xA54FF53A5F1D36F1
        self._e = 0x510E527FADE682D1
        self._f = 0x9B05688C2B3E6C1F
        self._g = 0x1F83D9ABFB41BD6B
        self._h = 0x5BE0CD19137E2179

        self._blocks_processed = 0
        self._buffer = bytearray()

        self.update(message)

    def _process_block(self, block: bytes) -> None:
        w: list[int] = list(unpack(8, False, block))

        i: int
        s0: int
        s1: int
        for i in range(16, 80):
            s0 = (
                right_rotate(w[i - 15], 1, 64)
                ^ right_rotate(w[i - 15], 8, 64)
                ^ (w[i - 15] >> 7)
            )
            s1 = (
                right_rotate(w[i - 2], 19, 64)
                ^ right_rotate(w[i - 2], 61, 64)
                ^ (w[i - 2] >> 6)
            )
            w.append((w[i - 16] + s0 + w[i - 7] + s1) % (2**64))

        a: int = self._a
        b: int = self._b
        c: int = self._c
        d: int = self._d
        e: int = self._e
        f: int = self._f
        g: int = self._g
        h: int = self._h

        ch: int
        temp0: int
        maj: int
        temp1: int
        for i in range(80):
            s1 = (
                right_rotate(e, 14, 64)
                ^ right_rotate(e, 18, 64)
                ^ right_rotate(e, 41, 64)
            )
            ch = (e & f) ^ ((~e) & g)
            temp0 = (h + s1 + ch + SHA512_CONSTANTS[i] + w[i]) % (2**64)
            s0 = (
                right_rotate(a, 28, 64)
                ^ right_rotate(a, 34, 64)
                ^ right_rotate(a, 39, 64)
            )
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp1 = (s0 + maj) % (2**64)

            h = g
            g = f
            f = e
            e = (d + temp0) % (2**64)
            d = c
            c = b
            b = a
            a = (temp0 + temp1) % (2**64)

        self._a = (self._a + a) % (2**64)
        self._b = (self._b + b) % (2**64)
        self._c = (self._c + c) % (2**64)
        self._d = (self._d + d) % (2**64)
        self._e = (self._e + e) % (2**64)
        self._f = (self._f + f) % (2**64)
        self._g = (self._g + g) % (2**64)
        self._h = (self._h + h) % (2**64)

    def update(self, message: bytes) -> None:
        self._buffer += message

        for _ in range(len(self._buffer) // 128):
            self._process_block(self._buffer[:128])

            self._blocks_processed += 1
            self._buffer = self._buffer[128:]

    def digest(self) -> bytes:
        # Save state.
        a: int = self._a
        b: int = self._b
        c: int = self._c
        d: int = self._d
        e: int = self._e
        f: int = self._f
        g: int = self._g
        h: int = self._h

        buffer_length: int = len(self._buffer)
        self._buffer += padding(
            (self._blocks_processed * 128) + buffer_length, 128, 16, False
        )

        self._process_block(self._buffer[:128])

        if len(self._buffer) == 256:
            self._process_block(self._buffer[128:])

        result: bytes = pack(
            8,
            False,
            self._a,
            self._b,
            self._c,
            self._d,
            self._e,
            self._f,
            self._g,
            self._h,
        )

        # Restore state.
        self._a = a
        self._b = b
        self._c = c
        self._d = d
        self._e = e
        self._f = f
        self._g = g
        self._h = h

        # Restore buffer.
        self._buffer = self._buffer[:buffer_length]

        return result

    def hexdigest(self) -> str:
        return self.digest().hex()
