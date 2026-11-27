"""LZOP compression and decompression.

LZOP is a gzip-like file compressor that wraps LZO1X-compressed blocks in a simple container format.

References:
    - https://www.lzop.org/
    - https://www.oberhumer.com/opensource/lzo/
"""

from __future__ import annotations

import io
import struct
import zlib
from typing import BinaryIO

from dissect.util.compression import lzo

LZOP_MAGIC = b"\x89LZO\x00\x0d\x0a\x1a\x0a"
HEADER_HAS_FILTER = 0x00000800
HEADER_HAS_ADLER32_D = 0x00000001
HEADER_HAS_ADLER32_C = 0x00000002
HEADER_HAS_CRC32_D = 0x00000100
HEADER_HAS_CRC32_C = 0x00000200
HEADER_OS_UNIX = 0x03000000

# Version, library version, version needed to extract, method, level, flags, mode, mtime low, mtime high and the
# length of the file name
_HEADER = struct.Struct(">HHHBBIIIIB")
_H = struct.Struct(">H")
_I = struct.Struct(">I")

# The values that lzop 1.04 with LZO 2.10 writes by default, for a file with mode 0644 and without a name
VERSION = 0x1040
LIBRARY_VERSION = 0x20A0
VERSION_NEEDED = 0x0940
METHOD = 1
LEVEL = 5
MODE = 0o100644
BLOCK_SIZE = 256 * 1024


def compress(src: bytes | BinaryIO) -> bytes:
    """LZOP compress from a file-like object or bytes.

    Args:
        src: File-like object or bytes to compress.

    Returns:
        The compressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    flags = HEADER_HAS_ADLER32_D | HEADER_OS_UNIX
    header = _HEADER.pack(VERSION, LIBRARY_VERSION, VERSION_NEEDED, METHOD, LEVEL, flags, MODE, 0, 0, 0)
    result = [LZOP_MAGIC, header, _I.pack(zlib.adler32(header))]

    while block := src.read(BLOCK_SIZE):
        buf = lzo.compress(block, header=False)
        if len(buf) >= len(block):
            # Uncompressed block
            buf = block

        result.append(_I.pack(len(block)) + _I.pack(len(buf)) + _I.pack(zlib.adler32(block)))
        result.append(buf)

    result.append(_I.pack(0))
    return b"".join(result)


def decompress(src: bytes | BinaryIO) -> bytes:
    """LZOP decompress from a file-like object or bytes.

    Args:
        src: File-like object or bytes to decompress.

    Returns:
        The decompressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    if src.read(9) != LZOP_MAGIC:
        raise ValueError("Invalid LZOP header")

    version = _H.unpack(src.read(2))[0]
    src.seek(5, io.SEEK_CUR)  # Skip library version (2), 'need to be extracted' version (2) and method (1)
    if version >= 0x0940:
        src.seek(1, io.SEEK_CUR)  # Skip level (1)

    flags = _I.unpack(src.read(4))[0]
    if flags & HEADER_HAS_FILTER:
        src.seek(4, io.SEEK_CUR)  # Skip filter info (4)

    # Every block has a checksum of its data for each of these flags, and of its compressed data if it's compressed
    data_checksum_size = 4 * (bool(flags & HEADER_HAS_ADLER32_D) + bool(flags & HEADER_HAS_CRC32_D))
    compressed_checksum_size = 4 * (bool(flags & HEADER_HAS_ADLER32_C) + bool(flags & HEADER_HAS_CRC32_C))

    src.seek(8, io.SEEK_CUR)  # Skip mode (4) and mtime_low (4)
    if version >= 0x0940:
        src.seek(4, io.SEEK_CUR)  # Skip mtime_high (4)

    i = src.read(1)[0]
    src.seek(i + 4, io.SEEK_CUR)  # Skip filename and checksum

    result = []
    while True:
        if len(buf := src.read(4)) < 4:
            # The stream ends without an end marker, all blocks have been read
            break

        if (uncompressed_block_size := _I.unpack(buf)[0]) == 0:
            break

        compressed_block_size = _I.unpack(src.read(4))[0]
        src.seek(data_checksum_size, io.SEEK_CUR)
        if compressed_block_size < uncompressed_block_size:
            src.seek(compressed_checksum_size, io.SEEK_CUR)

        buf = src.read(compressed_block_size)

        if uncompressed_block_size == compressed_block_size:
            # Uncompressed block
            result.append(buf)
        else:
            # Compressed block
            result.append(lzo.decompress(buf, header=False, buflen=uncompressed_block_size))

    return b"".join(result)
