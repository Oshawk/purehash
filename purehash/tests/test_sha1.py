from hashlib import sha1

from purehash._sha1 import SHA1
from purehash._util import random_tests


def test_md5():
    random_tests(sha1, SHA1, (55, 56, 57, 63, 64, 65))
