"""LZ4 compression and decompression.

This is the LZ4 block format, without the frame format.

References:
    - https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md
"""

from __future__ import annotations

import io
import struct
from typing import BinaryIO

from dissect.util.exceptions import CorruptDataError

_H = struct.Struct("<H")

MAX_OFFSET = 0xFFFF
MIN_MATCH = 4

# The last match must start at least 12 bytes before the end of the block, and the last 5 bytes are always literals
MF_LIMIT = 12
LAST_LITERALS = 5


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


def _put_length(dst: bytearray, length: int) -> None:
    if length < 0xF:
        return

    length -= 0xF
    while length >= 0xFF:
        dst.append(0xFF)
        length -= 0xFF
    dst.append(length)


def compress(src: bytes | BinaryIO) -> bytes:
    """LZ4 compress from a file-like object or bytes. Produces no header.

    Args:
        src: File-like object or bytes to compress.

    Returns:
        The compressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    data = src.read()
    dst = bytearray()

    # Only the last position of each 4 bytes is kept, and only for the start of a literal or match, which makes
    # compressing fast at the cost of a larger output
    positions = {}
    literal_offset = 0
    offset = 0

    while offset <= len(data) - MF_LIMIT:
        key = data[offset : offset + MIN_MATCH]
        match_offset = positions.get(key)
        positions[key] = offset

        if match_offset is None or offset - match_offset > MAX_OFFSET:
            # Literal, which is written together with the next match
            offset += 1
            continue

        length = MIN_MATCH
        while offset + length < len(data) - LAST_LITERALS and data[match_offset + length] == data[offset + length]:
            length += 1

        # Match, preceded by the literals since the previous match
        literal_len = offset - literal_offset
        dst.append((min(literal_len, 0xF) << 4) | min(length - MIN_MATCH, 0xF))
        _put_length(dst, literal_len)
        dst += data[literal_offset:offset]
        dst += _H.pack(offset - match_offset)
        _put_length(dst, length - MIN_MATCH)

        offset += length
        literal_offset = offset

    # The block ends with only literals
    literal_len = len(data) - literal_offset
    dst.append(min(literal_len, 0xF) << 4)
    _put_length(dst, literal_len)
    dst += data[literal_offset:]

    return bytes(dst)


def decompress(
    src: bytes | BinaryIO,
    uncompressed_size: int = -1,
    return_bytearray: bool = False,
    dictionary: bytes | None = None,
) -> bytes | tuple[bytes, int]:
    """LZ4 decompress from a file-like object or bytes up to a certain length. Assumes no header.

    Args:
        src: File-like object or bytes to decompress from.
        uncompressed_size: Ignored, present for compatibility with native lz4.
        return_bytearray: Whether to return ``bytearray`` or ``bytes``.
        dictionary: Optional data that matches may refer back into, as if it directly preceded the output.
                    To decompress a chain of dependent blocks (``LZ4_decompress_safe_continue``), pass the
                    previously decompressed data. Only the last 64 KiB can be referenced.

    Returns:
        The decompressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    # A match offset is 16 bits, so nothing before the last 64 KiB of the dictionary is reachable
    dst = bytearray(dictionary[-MAX_OFFSET:]) if dictionary else bytearray()
    dict_len = len(dst)
    max_len = dict_len + uncompressed_size if uncompressed_size > 0 else uncompressed_size
    min_match_len = 4

    while True:
        if len(read_buf := src.read(1)) == 0:
            raise CorruptDataError("EOF at reading literal-len")

        token = ord(read_buf)
        literal_len = _get_length(src, (token >> 4) & 0xF)

        if len(dst) + literal_len > max_len > 0:
            raise CorruptDataError("Decompressed size exceeds uncompressed_size")

        if len(read_buf := src.read(literal_len)) != literal_len:
            raise CorruptDataError("Not literal data")

        dst.extend(read_buf)
        if len(dst) >= max_len > 0:
            break

        if len(read_buf := src.read(2)) == 0:
            # The last sequence only has literals, decoders ignore the match length in its token
            break

        if len(read_buf) != 2:
            raise CorruptDataError("Premature EOF")

        if (offset := _H.unpack(read_buf)[0]) == 0:
            raise CorruptDataError("Offset can't be 0")

        if offset > len(dst):
            raise CorruptDataError("Offset is out of bounds")

        match_len = _get_length(src, (token >> 0) & 0xF)
        match_len += min_match_len

        if len(dst) + match_len > max_len > 0:
            raise CorruptDataError("Decompressed size exceeds uncompressed_size")

        if match_len <= offset:
            dst += dst[-offset : (-offset + match_len) or None]
        else:
            # The match overlaps the output it produces, so it repeats the last offset bytes.
            # Append those in bulk, growing dst at most twice instead of once per offset bytes.
            chunk = dst[-offset:]
            dst += chunk * (match_len // offset)
            dst += chunk[: match_len % offset]

        if len(dst) >= max_len > 0:
            break

    if dict_len:
        del dst[:dict_len]

    if not return_bytearray:
        dst = bytes(dst)

    return dst[:uncompressed_size] if uncompressed_size > 0 else dst
