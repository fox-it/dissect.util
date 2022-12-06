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

    dst.extend(block[:length])
    dst.extend(src.read(trailing))


def decompress(src: Union[bytes, BinaryIO], header: bool = True, buflen: int = -1) -> bytes:
    """LZO decompress from a file-like object or bytes. Assumes no header.

    Arguments are largely compatible with python-lzo API.

    Args:
        src: File-like object or bytes to decompress.
        header: Whether the metadata header is included in the input.
        buflen: If ``header`` is ``False``, a buffer length in bytes must be given that will fit the output.

    Returns:
        The decompressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    dst = bytearray()

    if header:
        byte = src.read(1)[0]
        if byte < 0xF0 or byte > 0xF1:
            raise ValueError("Invalid header value")
        out_len = struct.unpack("<I", src.read(4))
    else:
        out_len = buflen

    val = src.read(1)[0]
    if val == 0x10:
        raise ValueError("LZOv1")
    elif val >= 0x12:
        dst += src.read(val - 0x11)
        val = src.read(1)[0]

    trailing = 0
    while True:
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

        if len(dst) == out_len:
            break

        val = src.read(1)[0]

    return bytes(dst)
