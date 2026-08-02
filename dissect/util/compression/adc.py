# References:
# - https://github.com/Lekensteyn/dmg2img/blob/develop/adc.c
from __future__ import annotations

from typing import BinaryIO


def decompress(src: bytes | BinaryIO) -> bytes:
    """ADC (Apple Data Compression) decompress from a file-like object or bytes.

    Args:
        src: File-like object or bytes to decompress.

    Returns:
        The decompressed data.
    """
    if hasattr(src, "read"):
        src = src.read()

    dst = bytearray()
    pos = 0

    while pos < len(src):
        byte = src[pos]

        if byte & 0x80:
            count = (byte & 0x7F) + 1
            dst += src[pos + 1 : pos + 1 + count]
            pos += 1 + count
            continue

        if byte & 0x40:
            count = (byte & 0x3F) + 4
            distance = (src[pos + 1] << 8) + src[pos + 2] + 1
            pos += 3
        else:
            count = ((byte & 0x3F) >> 2) + 3
            distance = ((byte & 0x03) << 8) + src[pos + 1] + 1
            pos += 2

        if distance > len(dst):
            raise ValueError("Invalid match distance in ADC stream")

        for _ in range(count):
            dst.append(dst[-distance])

    return bytes(dst)
