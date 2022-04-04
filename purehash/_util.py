from random import choice, randbytes
from typing import Any


def left_rotate(number: int, rotation: int, bits: int) -> int:
    return ((number << rotation) % (2**bits)) | (number >> (bits - rotation))


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
