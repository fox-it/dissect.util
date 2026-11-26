"""Snappy compression and decompression.

This is the raw Snappy format, without the framing format.

References:
    - https://github.com/google/snappy/blob/main/format_description.txt
"""

from __future__ import annotations

import io
import struct
from collections import defaultdict, deque
from typing import BinaryIO

_H = struct.Struct("<H")
_I = struct.Struct("<I")

MIN_MATCH = 4
WINDOW = 65535
CHAIN_LIMIT = 128


def varint(src: BinaryIO) -> int:
    result = 0
    shift = 0

    while byte := src.read(1):
        value = byte[0]
        if value < 0x80:
            return result | (value << shift)
        result |= (value & 0x7F) << shift
        shift += 7

    raise EOFError("Unexpected EOF while reading varint")


def _put_literal(dst: bytearray, literal: bytes) -> None:
    length = len(literal) - 1
    if length < 60:
        dst.append(length << 2)
    else:
        # The length follows the tag in 1 to 4 bytes
        size = (length.bit_length() + 7) // 8
        dst.append((59 + size) << 2)
        dst += length.to_bytes(size, "little")
    dst += literal


def _put_copy(dst: bytearray, length: int, offset: int) -> None:
    if length < 12 and offset < 2048:
        dst.append(((offset >> 8) << 5) | ((length - 4) << 2) | 1)
        dst.append(offset & 0xFF)
    else:
        dst.append(((length - 1) << 2) | 2)
        dst += _H.pack(offset)


def compress(src: bytes | BinaryIO) -> bytes:
    """Snappy compress from a file-like object or bytes.

    Args:
        src: File-like object or bytes to compress.

    Returns:
        The compressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    data = src.read()

    # The preamble is the uncompressed length as a varint
    dst = bytearray()
    size = len(data)
    while size >= 0x80:
        dst.append((size & 0x7F) | 0x80)
        size >>= 7
    dst.append(size)

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

        if length == 0:
            # Literal, which is written together with the literals up to the next match
            chains[data[offset : offset + MIN_MATCH]].append(offset)
            offset += 1
            continue

        if literal_offset < offset:
            _put_literal(dst, data[literal_offset:offset])

        # Match, a copy is at most 64 bytes long, split so that the last copy is at least 4 bytes long
        remaining = length
        while remaining >= 68:
            _put_copy(dst, 64, distance)
            remaining -= 64
        if remaining > 64:
            _put_copy(dst, 60, distance)
            remaining -= 60
        _put_copy(dst, remaining, distance)

        for i in range(offset, offset + length):
            chains[data[i : i + MIN_MATCH]].append(i)
        offset += length
        literal_offset = offset

    if literal_offset < len(data):
        _put_literal(dst, data[literal_offset:])

    return bytes(dst)


def decompress(src: bytes | BinaryIO) -> bytes:
    """Snappy decompress from a file-like object or bytes.

    Decompresses until the stored uncompressed length in the preamble.

    Args:
        src: File-like object or bytes to decompress.

    Returns:
        The decompressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    dst = bytearray()

    uncompressed_length = varint(src)

    while len(dst) < uncompressed_length:
        tag_byte = src.read(1)[0]

        if (tag := tag_byte & 0b11) == 0:
            # Literal
            length = tag_byte >> 2
            if length < 60:
                length += 1
            elif length == 60:
                length = src.read(1)[0] + 1
            elif length == 61:
                length = _H.unpack(src.read(2))[0] + 1
            elif length == 62:
                length = _I.unpack(src.read(3) + b"\x00")[0] + 1
            elif length == 63:
                length = _I.unpack(src.read(4))[0] + 1

            if len(buf := src.read(length)) < length:
                raise EOFError("Unexpected EOF while reading literal")

            dst += buf
            continue

        # Copy with 1, 2 or 4 byte offset
        if tag == 1:
            length = ((tag_byte >> 2) & 0b111) + 4
            offset = ((tag_byte & 0b11100000) << 3) | src.read(1)[0]
        elif tag == 2:
            length = (tag_byte >> 2) + 1
            offset = _H.unpack(src.read(2))[0]
        else:
            length = (tag_byte >> 2) + 1
            offset = _I.unpack(src.read(4))[0]

        dst_offset = len(dst) - offset
        if dst_offset < 0 or offset == 0:
            raise ValueError("Invalid match distance")

        buf = dst[dst_offset : dst_offset + length]
        if offset - length <= 0:
            buf = (buf * ((length // len(buf)) + 1))[:length]

        dst += buf

    return bytes(dst)
