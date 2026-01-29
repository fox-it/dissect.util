# References:
# - https://github.com/google/snappy/blob/main/format_description.txt
from __future__ import annotations

import io
import struct
from typing import BinaryIO

_H = struct.Struct("<H")
_I = struct.Struct("<I")


def varint(src: BinaryIO) -> int:
    result = 0
    shift = 0

    while byte := src.read(1):
        value = byte[0]
        if value < 0x80:
            return result | (value << shift)
        result |= (value & 0x7F) << shift
        shift += 7

    raise EOFError("Unexpected EOF while reading varint")


def decompress(src: bytes | BinaryIO) -> bytes:
    """Snappy decompress from a file-like object or bytes.

    Decompresses until the stored uncompressed length in the preamble.

    Args:
        src: File-like object or bytes to decompress.

    Returns:
        The decompressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    dst = io.BytesIO()

    uncompressed_length = varint(src)

    while dst.tell() < uncompressed_length:
        tag_byte = src.read(1)[0]

        if (tag := tag_byte & 0b11) == 0:
            # Literal
            length = tag_byte >> 2
            if length < 60:
                length += 1
            elif length == 60:
                length = src.read(1)[0] + 1
            elif length == 61:
                length = _H.unpack(src.read(2))[0] + 1
            elif length == 62:
                length = _I.unpack(src.read(3) + b"\x00")[0] + 1
            elif length == 63:
                length = _I.unpack(src.read(4))[0] + 1

            if len(buf := src.read(length)) < length:
                raise EOFError("Unexpected EOF while reading literal")

            dst.write(buf)
            continue

        # Copy with 1, 2 or 4 byte offset
        if tag == 1:
            length = ((tag_byte >> 2) & 0b111) + 4
            offset = ((tag_byte & 0b11100000) << 3) | src.read(1)[0]
        elif tag == 2:
            length = (tag_byte >> 2) + 1
            offset = _H.unpack(src.read(2))[0]
        else:
            length = (tag_byte >> 2) + 1
            offset = _I.unpack(src.read(4))[0]

        dst_offset = dst.tell() - offset
        buf = dst.getbuffer()[dst_offset : dst_offset + length].tobytes()
        if offset - length <= 0:
            buf = (buf * ((length // len(buf)) + 1))[:length]

        dst.write(buf)

    return dst.getvalue()
