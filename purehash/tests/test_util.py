from random import getrandbits
import struct

from purehash._util import pack, unpack


SIZE_MAP = {
    1: "B",
    2: "H",
    4: "I",
    8: "Q",
}

LITTLE_ENDIAN_MAP = {True: "<", False: ">"}


def test_pack_unpack():
    for size in (1, 2, 4, 8):
        for little_endian in (True, False):
            for len_numbers in range(1, 5):
                numbers = tuple(getrandbits(size * 8) for _ in range(len_numbers))
                struct_format = LITTLE_ENDIAN_MAP[little_endian] + (
                    SIZE_MAP[size] * len_numbers
                )

                packed = pack(size, little_endian, *numbers)
                assert packed == struct.pack(struct_format, *numbers)

                unpacked = unpack(size, little_endian, packed)
                assert unpacked == struct.unpack(struct_format, packed)
