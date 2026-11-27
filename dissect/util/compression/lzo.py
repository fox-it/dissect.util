"""LZO compression and decompression.

This is the LZO1X format.

References:
    - https://github.com/FFmpeg/FFmpeg/blob/master/libavutil/lzo.c
    - https://docs.kernel.org/staging/lzo.html
    - https://github.com/torvalds/linux/blob/master/lib/lzo/lzo1x_decompress_safe.c
"""

from __future__ import annotations

import io
import struct
from collections import defaultdict, deque
from typing import BinaryIO

_H = struct.Struct("<H")
# The python-lzo header stores the decompressed size big endian
_I = struct.Struct(">I")

MAX_READ_LENGTH = (1 << 32) - 1000

MIN_MATCH = 3
WINDOW = 0xBFFF
CHAIN_LIMIT = 128

# The shortest encoding of a match has a length of 3 to 8 and a distance up to 2048
M2_MAX_MATCH = 8
M2_WINDOW = 0x800
# Longer matches up to 16384 bytes away are M3 matches, further away they are M4 matches
M3_WINDOW = 0x4000
M3_MAX_MATCH = 33
M4_MAX_MATCH = 9

# An M4 match with a distance of 16384 marks the end of the stream
END_OF_STREAM = b"\x11\x00\x00"


def _read_length(src: BinaryIO, val: int, mask: int) -> int:
    if (length := val & mask) != 0:
        return length

    while (val := src.read(1)[0]) == 0:
        if length >= MAX_READ_LENGTH:
            raise ValueError("Invalid encoded length")
        length += 255

    return length + mask + val


def _put_length(dst: bytearray, length: int) -> None:
    while length > 255:
        dst.append(0)
        length -= 255
    dst.append(length)


def _put_literal(dst: bytearray, literal: bytes, first: bool) -> None:
    if first and len(literal) <= 238:
        # The first instruction can be a literal with its length in the opcode
        dst.append(17 + len(literal))
    elif len(literal) <= 3:
        # Up to 3 literals are part of the previous match
        dst[-2] |= len(literal)
    elif len(literal) <= 18:
        dst.append(len(literal) - 3)
    else:
        dst.append(0)
        _put_length(dst, len(literal) - 18)
    dst += literal


def compress(src: bytes | BinaryIO, level: int = 1, header: bool = True) -> bytes:
    """LZO compress from a file-like object or bytes.

    Arguments are largely compatible with python-lzo API.

    Args:
        src: File-like object or bytes to compress.
        level: Ignored, all levels give the same output.
        header: Whether to include the metadata header in the output.

    Returns:
        The compressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    data = src.read()
    dst = bytearray()

    if header:
        dst.append(0xF0)
        dst += _I.pack(len(data))
    start = len(dst)

    chains = defaultdict(lambda: deque(maxlen=CHAIN_LIMIT))
    literal_offset = 0
    offset = 0

    while offset < len(data):
        length = 0
        distance = 0

        for match_offset in reversed(chains.get(data[offset : offset + MIN_MATCH], ())):
            if offset - match_offset > WINDOW:
                break

            match_length = MIN_MATCH
            while (
                offset + match_length < len(data) and data[match_offset + match_length] == data[offset + match_length]
            ):
                match_length += 1

            if match_length > length:
                length = match_length
                distance = offset - match_offset

        # A match of 3 bytes is only smaller than its literals in the shortest encoding
        if length == 0 or (length == MIN_MATCH and distance > M2_WINDOW):
            # Literal, which is written together with the literals up to the next match
            chains[data[offset : offset + MIN_MATCH]].append(offset)
            offset += 1
            continue

        if literal_offset < offset:
            _put_literal(dst, data[literal_offset:offset], len(dst) == start)

        # Match, the number of literals that follow is added to the low 2 bits of its second to last byte
        if length <= M2_MAX_MATCH and distance <= M2_WINDOW:
            dst.append(((length - 1) << 5) | (((distance - 1) & 7) << 2))
            dst.append((distance - 1) >> 3)
        elif distance <= M3_WINDOW:
            if length <= M3_MAX_MATCH:
                dst.append(0x20 | (length - 2))
            else:
                dst.append(0x20)
                _put_length(dst, length - M3_MAX_MATCH)
            dst += _H.pack((distance - 1) << 2)
        else:
            distance -= M3_WINDOW
            if length <= M4_MAX_MATCH:
                dst.append(0x10 | ((distance >> 11) & 8) | (length - 2))
            else:
                dst.append(0x10 | ((distance >> 11) & 8))
                _put_length(dst, length - M4_MAX_MATCH)
            dst += _H.pack((distance & 0x3FFF) << 2)

        for i in range(offset, offset + length):
            chains[data[i : i + MIN_MATCH]].append(i)
        offset += length
        literal_offset = offset

    if literal_offset < len(data):
        _put_literal(dst, data[literal_offset:], len(dst) == start)
    dst += END_OF_STREAM

    return bytes(dst)


def decompress(src: bytes | BinaryIO, header: bool = True, buflen: int = -1) -> bytes:
    """LZO decompress from a file-like object or bytes. Assumes no header.

    Arguments are largely compatible with python-lzo API.

    Args:
        src: File-like object or bytes to decompress.
        header: Whether the metadata header is included in the input.
        buflen: If ``header`` is ``False``, a buffer length in bytes must be given that will fit the output.

    Returns:
        The decompressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    dst = bytearray()

    if header:
        byte = src.read(1)[0]
        if byte not in [0xF0, 0xF1]:
            raise ValueError("Invalid header value")
        out_len = _I.unpack(src.read(4))[0]
    else:
        out_len = buflen

    offset = src.tell()
    src.seek(0, io.SEEK_END)
    src_size = src.tell() - offset
    src.seek(offset)

    # A first byte of 17 is followed by the bitstream version if the stream is at least 5 bytes long, a shorter stream
    # only has the end of stream marker
    val = src.read(1)[0]
    if val == 17 and src_size >= 5:
        _ = src.read(1)  # This would be the bitstream version but we don't currently use it
        val = src.read(1)[0]

    state = 0
    if val > 17:
        # Like the literals after a match, up to 3 literals can be followed by a match of 2 bytes, which uses the state
        state = val - 17
        dst += src.read(state)
        val = src.read(1)[0]

        # After 4 or more literals, a match of 3 bytes from at least 2049 bytes back can follow
        if val < 16 and state > 3:
            raise ValueError("Invalid match distance")

    while True:
        if val > 15:
            if val > 63:
                # Copy 3-8 bytes from block within 2kb distance
                length = (val >> 5) - 1
                dist = (src.read(1)[0] << 3) + ((val >> 2) & 7) + 1
            elif val > 31:
                # Copy of small block within 16kb distance
                length = _read_length(src, val, 31)
                val = src.read(1)[0]
                dist = (src.read(1)[0] << 6) + (val >> 2) + 1
            else:
                # Copy of a block within 16...48kB distance
                length = _read_length(src, val, 7)
                dist = (1 << 14) + ((val & 8) << 11)
                val = src.read(1)[0]
                dist += (src.read(1)[0] << 6) + (val >> 2)
                if dist == (1 << 14):
                    if length != 1:
                        raise ValueError("Invalid LZO stream")
                    break
        elif not state:
            # Copy 4 or more literals, depending on the last 4 bits
            length = _read_length(src, val, 15)
            dst += src.read(length + 3)
            val = src.read(1)[0]
            if val > 15:
                continue
            length = 1
            dist = (1 << 11) + (src.read(1)[0] << 2) + (val >> 2) + 1
        else:
            length = 0
            dist = (src.read(1)[0] << 2) + (val >> 2) + 1

        if dist > len(dst):
            raise ValueError("Invalid match distance")

        match_len = length + 2
        if match_len <= dist:
            dst += dst[-dist : (-dist + match_len) or None]
        else:
            # The match overlaps the output it produces, so it repeats the last dist bytes
            chunk = dst[-dist:]
            dst += chunk * (match_len // dist)
            dst += chunk[: match_len % dist]

        # State is often encoded in the last 2 bits of the value, and used in subsequent iterations
        state = length = val & 3
        dst += src.read(length)

        if len(dst) == out_len:
            break

        val = src.read(1)[0]

    return bytes(dst)
