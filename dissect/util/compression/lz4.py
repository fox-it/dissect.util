"""LZ4 block-format compression and decompression."""

from __future__ import annotations

import io
import struct
from typing import BinaryIO

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
    src: bytes | BinaryIO,
    uncompressed_size: int = -1,
    return_bytearray: bool = False,
) -> bytes | tuple[bytes, int]:
    """LZ4 decompress from a file-like object or bytes up to a certain length. Assumes no header.

    Args:
        src: File-like object or bytes to decompress from.
        uncompressed_size: Ignored, present for compatibility with native lz4.
        return_bytearray: Whether to return ``bytearray`` or ``bytes``.

    Returns:
        The decompressed data.

    Raises:
        CorruptDataError: If the input is truncated, malformed, or exceeds ``uncompressed_size``.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    dst = bytearray()
    min_match_len = 4

    while True:
        if len(read_buf := src.read(1)) == 0:
            raise CorruptDataError("EOF at reading literal-len")

        token = ord(read_buf)
        literal_len = _get_length(src, (token >> 4) & 0xF)

        if len(dst) + literal_len > uncompressed_size > 0:
            raise CorruptDataError("Decompressed size exceeds uncompressed_size")

        if len(read_buf := src.read(literal_len)) != literal_len:
            raise CorruptDataError("Not literal data")

        dst.extend(read_buf)
        if len(dst) >= uncompressed_size > 0:
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

        match_len = _get_length(src, (token >> 0) & 0xF)
        match_len += min_match_len

        if len(dst) + match_len > uncompressed_size > 0:
            raise CorruptDataError("Decompressed size exceeds uncompressed_size")

        remaining = match_len
        while remaining > 0:
            match_size = min(remaining, offset)
            dst += dst[-offset : (-offset + match_size) or None]
            remaining -= match_size

        if len(dst) >= uncompressed_size > 0:
            break

    if not return_bytearray:
        dst = bytes(dst)

    return dst[:uncompressed_size] if uncompressed_size > 0 else dst


# --- LZ4 block encoder ---

_MIN_MATCH = 4
"""Minimum match length (lz4_Block_format.md)."""

_MAX_OFFSET = 0xFFFF
"""Largest encodable back-reference distance (lz4_Block_format.md)."""

_TOKEN_MAX = 15
"""Nibble value meaning "length continues in extra bytes" (lz4_Block_format.md)."""

_LAST_LITERALS = 5
"""End-of-block invariant: the last 5 bytes are always literals (lz4_Block_format.md)."""

_MF_LIMIT = 12
"""End-of-block invariant: last match starts at least 12 bytes before end (lz4_Block_format.md)."""


def _emit_length_extension(out: bytearray, remainder: int) -> None:
    """Emit 0xFF-continuation bytes for a length whose nibble was 15.

    Per lz4_Block_format.md each byte (0-255) adds to the length, and a 255
    byte forces another.  An exact multiple of 255 is terminated by an
    explicit 0 byte.
    """
    while remainder >= 0xFF:
        out.append(0xFF)
        remainder -= 0xFF
    out.append(remainder)


def _emit_sequence(out: bytearray, literals: bytes, offset: int, match_len: int) -> None:
    """Emit one full sequence: token, literal run, offset, match length.

    A ``match_len`` of 0 marks the final literals-only sequence (no offset
    field) -- the block-format end condition that the last sequence contains
    only literals.
    """
    literal_len = len(literals)
    literal_nibble = min(literal_len, _TOKEN_MAX)
    match_nibble = 0 if match_len == 0 else min(match_len - _MIN_MATCH, _TOKEN_MAX)
    out.append((literal_nibble << 4) | match_nibble)
    if literal_nibble == _TOKEN_MAX:
        _emit_length_extension(out, literal_len - _TOKEN_MAX)
    out += literals
    if match_len == 0:
        return
    out += offset.to_bytes(2, "little")
    if match_nibble == _TOKEN_MAX:
        _emit_length_extension(out, match_len - _MIN_MATCH - _TOKEN_MAX)


def compress(src: bytes | BinaryIO, return_bytearray: bool = False) -> bytes:
    """LZ4 compress to a headerless block.

    Greedy hash-table matcher honouring all end-of-block invariants from the
    LZ4 block format specification: matches are at least 4 bytes, reach back
    at most 65535 bytes, start at least 12 bytes before the end, and stop 5
    bytes short so the block ends in a literals-only sequence.

    Args:
        src: Data to compress, as bytes or a file-like object.
        return_bytearray: Whether to return ``bytearray`` instead of ``bytes``.

    Returns:
        The compressed LZ4 block (no frame header, no checksum).
    """
    if hasattr(src, "read"):
        src = src.read()

    data = bytes(src)
    n = len(data)
    out = bytearray()

    if n == 0:
        # A single zero token: empty final literal run.
        out.append(0x00)
        if not return_bytearray:
            return bytes(out)
        return out

    table: dict[bytes, int] = {}
    match_limit = n - _LAST_LITERALS
    anchor = 0
    pos = 0

    while pos <= n - _MF_LIMIT:
        key = data[pos : pos + _MIN_MATCH]
        candidate = table.get(key)
        table[key] = pos

        if candidate is None or pos - candidate > _MAX_OFFSET:
            pos += 1
            continue

        # dict key equality guarantees the first _MIN_MATCH bytes match.
        match_len = _MIN_MATCH
        while pos + match_len < match_limit and data[candidate + match_len] == data[pos + match_len]:
            match_len += 1

        _emit_sequence(out, data[anchor:pos], pos - candidate, match_len)
        pos += match_len
        anchor = pos

    # Final literals-only sequence.
    _emit_sequence(out, data[anchor:], 0, 0)

    if not return_bytearray:
        return bytes(out)
    return out
