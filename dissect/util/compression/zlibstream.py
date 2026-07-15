"""ZLIB (RFC 1950) compression and decompression.

Used by ntdll.dll RtlCompressBuffer with COMPRESSION_FORMAT_ZLIB (0x0008).
"""

from __future__ import annotations

import zlib as _zlib
from typing import BinaryIO


def decompress(src: bytes | BinaryIO) -> bytes:
    """Decompress a ZLIB stream (RFC 1950 header + DEFLATE + Adler-32).

    Args:
        src: File-like object or bytes to decompress.

    Returns:
        The decompressed data.
    """
    if hasattr(src, "read"):
        src = src.read()
    return _zlib.decompress(src)


def compress(src: bytes | BinaryIO, level: int = 1) -> bytes:
    """Compress data into a ZLIB stream (RFC 1950).

    Args:
        src: File-like object or bytes to compress.
        level: Compression level 0-9 (default 1).

    Returns:
        The compressed ZLIB stream.
    """
    if hasattr(src, "read"):
        src = src.read()
    return _zlib.compress(src, level)
