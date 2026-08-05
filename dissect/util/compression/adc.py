# References:
# - https://github.com/Lekensteyn/dmg2img/blob/develop/adc.c
from __future__ import annotations

import io
from typing import BinaryIO


def decompress(src: bytes | BinaryIO) -> bytes:
    """ADC (Apple Data Compression) decompress from a file-like object or bytes.

    Args:
        src: File-like object or bytes to decompress.

    Returns:
        The decompressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    dst = bytearray()

    while _byte := src.read(1):
        byte = _byte[0]

        if byte & 0x80:
            count = (byte & 0x7F) + 1
            dst.extend(src.read(count))
            continue

        if byte & 0x40:
            count = (byte & 0x3F) + 4
            extra = src.read(2)
            distance = (extra[0] << 8) + extra[1] + 1
        else:
            count = ((byte & 0x3F) >> 2) + 3
            extra = src.read(1)
            distance = ((byte & 0x03) << 8) + extra[0] + 1

        if distance > len(dst):
            raise ValueError("Invalid match distance in ADC stream")

        for _ in range(count):
            dst.append(dst[-distance])

    return bytes(dst)
