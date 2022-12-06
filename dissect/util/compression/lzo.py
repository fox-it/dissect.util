import io
import struct
from typing import BinaryIO, Union


def _count_zeroes(src: BinaryIO):
    length = 0
    val = src.read(1)[0]
    while val == 0:
        length += 255
        val = src.read(1)[0]
        if length > 2**20:
            raise ValueError("Too many zeroes")

    return length + val


def _copy_block(src: BinaryIO, dst: bytearray, length: int, distance: int, trailing: int):
    remaining = length

    block = dst[-distance:]
    remaining -= len(block)
    while remaining > 0:
        add = block[:remaining]
        remaining -= len(add)
        block += add

    dst.extend(block)
    dst.extend(src.read(trailing))


def decompress(src: Union[bytes, BinaryIO]) -> bytes:
    """LZO decompress from a file-like object or bytes. Assumes no header.

    Args:
        src: File-like object or bytes to decompress.

    Returns:
        The decompressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    dst = bytearray()

    first = True
    trailing = 0
    while True:
        val = src.read(1)[0]
        if first and val == 0x10:
            raise ValueError("LZOv1")
        elif first and val >= 0x12:
            dst += src.read(val - 0x11)
            first = False
            continue
        first = False

        if val <= 0xF:
            if not trailing:
                if val == 0:
                    dst += src.read(_count_zeroes(src) + 18)
                else:
                    dst += src.read(val + 3)
            else:
                h = src.read(1)[0]
                dist = (h << 2) + (val >> 2) + 1
                length = 2
                trailing = val & 3
                _copy_block(src, dst, length, dist, trailing)
        elif val <= 0x1F:
            if val & 7 == 0:
                length = 9 + _count_zeroes(src)
            else:
                length = (val & 7) + 2
            ds = struct.unpack("<H", src.read(2))[0]
            dist = 16384 + ((val & 8) >> 3) + (ds >> 2)
            if dist == 16384:
                break
            trailing = ds & 3
            _copy_block(src, dst, length, dist, trailing)
        elif val <= 0x3F:
            length = val & 31
            if length == 0:
                length = _count_zeroes(src) + 31
            length += 2
            ds = struct.unpack("<H", src.read(2))[0]
            dist = 1 + (ds >> 2)
            trailing = ds & 3
            _copy_block(src, dst, length, dist, trailing)
        else:
            if val <= 0x7F:
                length = 3 + ((val >> 5) & 1)
            else:
                length = 5 + ((val >> 5) & 3)
            h = src.read(1)[0]
            d = (val >> 2) & 7
            dist = (h << 3) + d + 1
            trailing = val & 3
            _copy_block(src, dst, length, dist, trailing)

    return bytes(dst)
