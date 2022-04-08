class Hash:
    _blocks_processed: int
    _buffer: bytearray

    def __init__(self, message: bytes = b"") -> None:
        self._blocks_processed = 0
        self._buffer = bytearray()

        self.update(message)

    def update(self, message: bytes) -> None:
        pass

    def digest(self) -> bytes:
        pass

    def hexdigest(self) -> str:
        return self.digest().hex()
