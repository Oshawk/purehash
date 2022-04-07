from __future__ import annotations
from random import choice, getrandbits
from typing import Any


def left_rotate(number: int, rotation: int, bits: int) -> int:
    rotation = rotation % bits
    return ((number << rotation) % (2**bits)) | (number >> (bits - rotation))


def right_rotate(number: int, rotation: int, bits: int) -> int:
    rotation = rotation % bits
    return left_rotate(number, bits - rotation, bits)


def pack(size: int, little_endian: bool, *args: int) -> bytes:
    result: bytearray = bytearray()

    number: int
    for number in args:
        packed: bytearray = bytearray()
        for _ in range(size):
            byte: int = number % (2**8)
            number >>= 8
            if little_endian:
                packed.append(byte)
            else:
                packed.insert(0, byte)

        result += packed

    return bytes(result)


def unpack(size: int, little_endian: bool, bytes_: bytes) -> tuple[int, ...]:
    assert len(bytes_) % size == 0, "Length of bytes_ must be a multiple of size."

    result: list[int] = []

    i: int
    for i in range(0, len(bytes_), size):
        packed: bytearray = bytearray(bytes_[i : i + size])
        number: int = 0
        for _ in range(size):
            number <<= 8

            byte: int
            if little_endian:
                byte = packed.pop()
            else:
                byte = packed.pop(0)

            number += byte

        result.append(number)

    return tuple(result)


def padding(
    length: int, block_size: int, length_size: int, length_little_endian: bool
) -> bytes:
    padding_: bytearray = bytearray(b"\x80")

    length_mod: int = length % block_size
    if length_mod < (block_size - (block_size // 8)):
        padding_ += b"\x00" * (block_size - (block_size // 8) - 1 - length_mod)
    else:
        padding_ += b"\x00" * (block_size * 2 - (block_size // 8) - 1 - length_mod)

    padding_ += pack(length_size, length_little_endian, length * 8)

    return bytes(padding_)


def random_tests(x: Any, y: Any, problem_lengths: tuple[int, ...]) -> None:
    lengths: tuple[int, ...] = (0, 1) + problem_lengths

    length: int
    r: bytes
    for _ in range(16):
        length = choice(lengths)
        r = pack(1, False, *(getrandbits(8) for _ in range(length)))

        x_: Any = x(r)
        y_: Any = y(r)

        assert x_.digest() == y_.digest()
        assert x_.hexdigest() == y_.hexdigest()

        for _ in range(16):
            length = choice(lengths)
            r = pack(1, False, *(getrandbits(8) for _ in range(length)))

            x_.update(r)
            y_.update(r)

            assert x_.digest() == y_.digest()
            assert x_.hexdigest() == y_.hexdigest()
