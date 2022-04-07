# PureHash

Pure Python implementations of common hashing algorithms.

## Installation

```
pip install purehash
```

## Usage

Usage is similar to that of `hashlib`, for example:

```python
import purehash

m = purehash.md5(b"The quick brown fox ")
m.update(b"jumps over the lazy dog.")
m.digest()  # b"\xe4\xd9\t\xc2\x90\xd0\xfb\x1c\xa0h\xff\xad\xdf"\xcb\xd0"
m.hexdigest()  # "e4d909c290d0fb1ca068ffaddf22cbd0"
```

## Supported Hash Algorithms

- MD5 (`md5`)
- SHA-1 (`sha1`)
- SHA-256 (`sha256`)
- SHA-512 (`sha256`)
