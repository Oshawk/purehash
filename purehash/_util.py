from random import choice, randbytes
from struct import pack
from typing import Any


def left_rotate(number: int, rotation: int, bits: int) -> int:
    rotation = rotation % bits
    return ((number << rotation) % (2**bits)) | (number >> (bits - rotation))


def right_rotate(number: int, rotation: int, bits: int) -> int:
    rotation = rotation % bits
    return left_rotate(number, bits - rotation, bits)


def padding(length: int, block_size: int, little_endian: bool) -> bytes:
    padding_: bytearray = bytearray(b"\x80")

    length_mod: int = length % block_size
    if length_mod < (block_size - (block_size // 8)):
        padding_ += b"\x00" * (block_size - (block_size // 8) - 1 - length_mod)
    else:
        padding_ += b"\x00" * (block_size * 2 - (block_size // 8) - 1 - length_mod)

    extra_length: bytes
    if block_size == 128:
        extra_length = pack(f"""{"<" if little_endian else ">"}Q""", ((length * 8) >> 64) % (2 ** 64))
    else:
        extra_length = b""

    if not little_endian:
        padding_ += extra_length

    padding_ += pack(f"""{"<" if little_endian else ">"}Q""", (length * 8) % (2**64))

    if little_endian:
        padding_ += extra_length

    return bytes(padding_)


def random_tests(x: Any, y: Any, problem_lengths: tuple[int, ...]) -> None:
    lengths: tuple[int, ...] = (0, 1) + problem_lengths

    r: bytes
    for _ in range(8):
        r = randbytes(choice(lengths))

        x_: Any = x(r)
        y_: Any = y(r)

        assert x_.digest() == y_.digest()
        assert x_.hexdigest() == y_.hexdigest()

        for _ in range(8):
            r = randbytes(choice(lengths))

            x_.update(r)
            y_.update(r)

            assert x_.digest() == y_.digest()
            assert x_.hexdigest() == y_.hexdigest()
