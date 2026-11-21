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


# Compression

_MIN_MATCH = 4  # Minimum match length (lz4_Block_format.md)

_TOKEN_MAX = 15  # Nibble value meaning "length continues in extra bytes" (lz4_Block_format.md)

_LAST_LITERALS = 5  # End-of-block invariant: the last 5 bytes are always literals (lz4_Block_format.md)

_MF_LIMIT = 12  # End-of-block invariant: last match starts at least 12 bytes before end (lz4_Block_format.md)


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


def compress(src: bytes | BinaryIO) -> bytes:
    """LZ4 compress to a headerless block.

    Greedy hash-table matcher honouring all end-of-block invariants from the
    LZ4 block format specification: matches are at least 4 bytes, reach back
    at most 65535 bytes, start at least 12 bytes before the end, and stop 5
    bytes short so the block ends in a literals-only sequence.

    Args:
        src: Data to compress, as bytes or a file-like object.

    Returns:
        The compressed LZ4 block (no frame header, no checksum).
    """
    if hasattr(src, "read"):
        src = src.read()

    data = bytes(src)
    n = len(data)
    if n == 0:
        # A single zero token: empty final literal run.
        return b"\x00"

    out = bytearray()
    table: dict[bytes, int] = {}
    match_limit = n - _LAST_LITERALS
    anchor = 0
    pos = 0

    while pos <= n - _MF_LIMIT:
        key = data[pos : pos + _MIN_MATCH]
        candidate = table.get(key)
        table[key] = pos

        if candidate is None or pos - candidate > MAX_OFFSET:
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

    return bytes(out)
