from __future__ import annotations

import io
from typing import BinaryIO

from dissect.util.compression import lzo

HEADER_HAS_FILTER = 0x00000800


def decompress(src: bytes | BinaryIO) -> bytes:
    """LZOP decompress from a file-like object or bytes.

    Args:
        src: File-like object or bytes to decompress.

    Returns:
        The decompressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    if src.read(9) != b"\x89LZO\x00\x0d\x0a\x1a\x0a":
        raise ValueError("Invalid LZOP header")

    version = int.from_bytes(src.read(2), "big")
    src.seek(5, io.SEEK_CUR)  # Skip library version (2), 'need to be extracted' version (2) and method (1)
    if version >= 0x0940:
        src.seek(1, io.SEEK_CUR)  # Skip level (1)

    if int.from_bytes(src.read(4), "big") & HEADER_HAS_FILTER:
        src.seek(4, io.SEEK_CUR)  # Skip filter info (4)

    src.seek(8, io.SEEK_CUR)  # Skip mode (4) and mtime_low (4)
    if version >= 0x0940:
        src.seek(4, io.SEEK_CUR)  # Skip mtime_high (4)

    i = src.read(1)[0]
    src.seek(i + 4, io.SEEK_CUR)  # Skip filename and checksum

    result = []
    while True:
        uncompressed_block_size = int.from_bytes(src.read(4), "big")

        if uncompressed_block_size == 0:
            break

        compressed_block_size = int.from_bytes(src.read(4), "big")
        src.seek(4, io.SEEK_CUR)  # Skip checksum

        buf = src.read(compressed_block_size)

        if uncompressed_block_size == compressed_block_size:
            # Uncompressed block
            result.append(buf)
        else:
            # Compressed block
            result.append(lzo.decompress(buf, header=False, buflen=uncompressed_block_size))

    return b"".join(result)
