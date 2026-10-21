"""Raw DEFLATE (RFC 1951) compression and decompression without zlib or gzip wrappers.

Used by ntdll.dll RtlCompressBuffer with COMPRESSION_FORMAT_DEFLATE (0x0007).
"""

from __future__ import annotations

import zlib as _zlib
from typing import BinaryIO


def decompress(src: bytes | BinaryIO, max_size: int | None = None) -> bytes:
    """Decompress a raw DEFLATE stream (RFC 1951, no zlib/gzip wrapper).

    Args:
        src: File-like object or bytes to decompress.
        max_size: Optional maximum output size in bytes. When set, raises
            a zlib.error if the decompressed output would exceed this limit.

    Returns:
        The decompressed data.

    Raises:
        zlib.error: If the input is malformed or the output exceeds ``max_size``.
    """
    if hasattr(src, "read"):
        src = src.read()
    if max_size is not None:
        dc = _zlib.decompressobj(wbits=-15)
        result = dc.decompress(src, max_size)
        if dc.unconsumed_tail:
            raise _zlib.error("DEFLATE output exceeds max_size")
        return result
    return _zlib.decompress(src, -15)


def compress(src: bytes | BinaryIO, level: int = 1) -> bytes:
    """Compress data into a raw DEFLATE stream (RFC 1951, no wrapper).

    Args:
        src: File-like object or bytes to compress.
        level: Compression level 0-9 (default 1).

    Returns:
        The compressed raw DEFLATE bitstream.

    Raises:
        zlib.error: If the input cannot be compressed or the level is invalid.
    """
    if hasattr(src, "read"):
        src = src.read()
    c = _zlib.compressobj(level, _zlib.DEFLATED, -15)
    return c.compress(src) + c.flush()
