from __future__ import annotations

import io
import struct
from typing import BinaryIO, cast

from dissect.util.exceptions import CorruptDataError


def _get_length(src: BinaryIO, length: int) -> int:
    if length != 0xF:
        return length

    while True:
        read_buf = src.read(1)
        if len(read_buf) != 1:
            raise CorruptDataError("EOF at length read")
        len_part = ord(read_buf)
        length += len_part

        if len_part != 0xFF:
            break

    return length


def decompress(
    src: bytes | bytearray | memoryview | BinaryIO,
    uncompressed_size: int = -1,
    max_length: int = -1,
    return_bytearray: bool = False,
    return_bytes_read: bool = False,
) -> bytes | bytearray | tuple[bytes | bytearray, int]:
    """LZ4 decompress from a file-like object up to a certain length. Assumes no header.

    Args:
        src: File-like object to decompress from.
        uncompressed_size: Ignored, present for compatibility with native lz4. The ``max_length``
                           parameter sort-of but not completely has the same function.
        max_length: Decompress up to this many result bytes.
        return_bytearray: Whether to return ``bytearray`` or ``bytes``.
        return_bytes_read: Whether to return a tuple of ``(data, bytes_read)`` or just the data.

    Returns:
        The decompressed data or a tuple of the decompressed data and the amount of bytes read.
    """
    if isinstance(src, (bytes, bytearray, memoryview)):
        src = io.BytesIO(src)

    dst = bytearray()
    start = src.tell()
    min_match_len = 4

    while True:
        read_buf = src.read(1)
        if len(read_buf) == 0:
            raise CorruptDataError("EOF at reading literal-len")

        token = ord(read_buf)
        literal_len = _get_length(src, (token >> 4) & 0xF)

        read_buf = src.read(literal_len)

        if len(read_buf) != literal_len:
            raise CorruptDataError("Not literal data")
        dst.extend(read_buf)

        if len(dst) == max_length:
            break

        read_buf = src.read(2)
        if len(read_buf) == 0:
            token_and = token & 0xF
            if token_and != 0:
                raise CorruptDataError(f"EOF, but match-len > 0: {token_and}")
            break

        if len(read_buf) != 2:
            raise CorruptDataError("Premature EOF")

        (offset,) = cast(tuple[int], struct.unpack("<H", read_buf))

        if offset == 0:
            raise CorruptDataError("Offset can't be 0")

        match_len = _get_length(src, (token >> 0) & 0xF)
        match_len += min_match_len

        for _ in range(match_len):
            dst.append(dst[-offset])

    if not return_bytearray:
        dst = bytes(dst)

    if return_bytes_read:
        return dst, src.tell() - start

    return dst
