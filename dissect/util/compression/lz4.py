from __future__ import annotations

import io
import struct
from typing import BinaryIO

from dissect.util.exceptions import CorruptDataError

MAX_OFFSET = 0xFFFF


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
            token_and = token & 0xF
            if token_and != 0:
                raise CorruptDataError(f"EOF, but match-len > 0: {token_and}")
            break

        if len(read_buf) != 2:
            raise CorruptDataError("Premature EOF")

        if (offset := struct.unpack("<H", read_buf)[0]) == 0:
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
