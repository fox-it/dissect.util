from __future__ import annotations

from functools import lru_cache


@lru_cache(maxsize=32)
def _table(width: int, poly: int, reflected: bool) -> tuple[int, ...]:
    """Generate a CRC lookup table.

    Args:
        width: The width of the CRC in bits.
        poly: The polynomial in normal (MSB-first) notation.
        reflected: Whether the CRC is reflected (LSB-first).
    """
    mask = (1 << width) - 1
    table = []

    if reflected:
        rpoly = int(f"{poly:0{width}b}"[::-1], 2)
        for i in range(256):
            crc = i
            for _ in range(8):
                crc = (crc >> 1) ^ rpoly if crc & 1 else crc >> 1
            table.append(crc)
    else:
        top = 1 << (width - 1)
        for i in range(256):
            crc = i << (width - 8)
            for _ in range(8):
                crc = ((crc << 1) ^ poly) & mask if crc & top else (crc << 1) & mask
            table.append(crc)

    return tuple(table)


class _Crc:
    width: int

    def __init__(self, poly: int, init: int = 0, xorout: int = 0, reflected: bool = True):
        """A table-driven CRC with arbitrary parameters.

        Parameters follow the CRC catalogue (https://reveng.sourceforge.io/crc-catalogue/), where ``refin`` and
        ``refout`` are combined into ``reflected``.

        Args:
            poly: The polynomial in normal (MSB-first) notation, e.g. ``0x04C11DB7`` for the standard CRC-32.
            init: The initial value of the register.
            xorout: The value to XOR the final register with.
            reflected: Whether the CRC is reflected (LSB-first).
        """
        mask = (1 << self.width) - 1
        if not (0 <= poly <= mask and 0 <= init <= mask and 0 <= xorout <= mask):
            raise ValueError(f"CRC parameters must fit in {self.width} bits")

        self.poly = poly
        self.init = init
        self.xorout = xorout
        self.reflected = reflected
        self.table = _table(self.width, poly, reflected)

    def __repr__(self) -> str:
        digits = self.width // 4
        return (
            f"<{type(self).__name__} poly={self.poly:#0{digits + 2}x} init={self.init:#0{digits + 2}x} "
            f"xorout={self.xorout:#0{digits + 2}x} reflected={self.reflected}>"
        )

    def _update(self, crc: int, data: bytes) -> int:
        table = self.table

        if self.reflected:
            for b in data:
                crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8)
        else:
            mask = (1 << self.width) - 1
            shift = self.width - 8
            for b in data:
                crc = table[((crc >> shift) ^ b) & 0xFF] ^ ((crc << 8) & mask)

        return crc

    def update(self, crc: int, data: bytes) -> int:
        """Update a checksum with data.

        Args:
            crc: A previously computed checksum to continue from.
            data: The data to update the checksum with.
        """
        return self._update(crc ^ self.xorout, data) ^ self.xorout

    def __call__(self, data: bytes, value: int | None = None) -> int:
        """Calculate the checksum of some data, optionally continuing from a previous checksum.

        Args:
            data: The data to calculate the checksum of.
            value: A previously computed checksum to continue from. Default is to start a new checksum.
        """
        if value is None:
            return self._update(self.init, data) ^ self.xorout
        return self.update(value, data)


class Crc32(_Crc):
    width = 32


class Crc64(_Crc):
    width = 64
