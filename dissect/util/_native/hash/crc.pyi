from __future__ import annotations


class Crc32:
    poly: int
    init: int
    xorout: int
    reflected: bool
    table: tuple[int, ...]

    def __init__(self, poly: int, init: int = 0, xorout: int = 0, reflected: bool = True) -> None: ...
    def update(self, crc: int, data: bytes) -> int: ...
    def __call__(self, data: bytes, value: int | None = None) -> int: ...


class Crc64:
    poly: int
    init: int
    xorout: int
    reflected: bool
    table: tuple[int, ...]

    def __init__(self, poly: int, init: int = 0, xorout: int = 0, reflected: bool = True) -> None: ...
    def update(self, crc: int, data: bytes) -> int: ...
    def __call__(self, data: bytes, value: int | None = None) -> int: ...
