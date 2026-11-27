"""ADC compression and decompression.

ADC (Apple Data Compression) is an LZ77-type compression that DMG disk images can use.

References:
    - https://github.com/Lekensteyn/dmg2img/blob/develop/adc.c
"""

from __future__ import annotations

import io
import struct
from collections import defaultdict, deque
from typing import BinaryIO

_H = struct.Struct(">H")

MIN_MATCH = 3
MAX_MATCH = 67
MAX_LITERAL = 128
WINDOW = 65536
CHAIN_LIMIT = 128

# Short matches are encoded in 2 bytes instead of 3
SHORT_MAX_MATCH = 18
SHORT_WINDOW = 1024


def _put_literal(dst: bytearray, literal: bytes) -> None:
    for i in range(0, len(literal), MAX_LITERAL):
        chunk = literal[i : i + MAX_LITERAL]
        dst.append(0x80 | (len(chunk) - 1))
        dst += chunk


def compress(src: bytes | BinaryIO) -> bytes:
    """ADC (Apple Data Compression) compress from a file-like object or bytes.

    Args:
        src: File-like object or bytes to compress.

    Returns:
        The compressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    data = src.read()
    dst = bytearray()

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
                match_length < MAX_MATCH
                and offset + match_length < len(data)
                and data[match_offset + match_length] == data[offset + match_length]
            ):
                match_length += 1

            if match_length > length:
                length = match_length
                distance = offset - match_offset

                # A longer match isn't possible
                if length == MAX_MATCH:
                    break

        # A match of 3 bytes only has a short encoding
        if length == 0 or (length == MIN_MATCH and distance > SHORT_WINDOW):
            # Literal, which is written together with the literals up to the next match
            chains[data[offset : offset + MIN_MATCH]].append(offset)
            offset += 1
            continue

        _put_literal(dst, data[literal_offset:offset])

        # Match
        if length <= SHORT_MAX_MATCH and distance <= SHORT_WINDOW:
            dst.append(((length - MIN_MATCH) << 2) | ((distance - 1) >> 8))
            dst.append((distance - 1) & 0xFF)
        else:
            dst.append(0x40 | (length - 4))
            dst += _H.pack(distance - 1)

        for i in range(offset, offset + length):
            chains[data[i : i + MIN_MATCH]].append(i)
        offset += length
        literal_offset = offset

    _put_literal(dst, data[literal_offset:])

    return bytes(dst)


def decompress(src: bytes | BinaryIO) -> bytes:
    """ADC (Apple Data Compression) decompress from a file-like object or bytes.

    Args:
        src: File-like object or bytes to decompress.

    Returns:
        The decompressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    dst = bytearray()

    while _byte := src.read(1):
        byte = _byte[0]

        if byte & 0x80:
            count = (byte & 0x7F) + 1
            dst.extend(src.read(count))
            continue

        if byte & 0x40:
            count = (byte & 0x3F) + 4
            extra = src.read(2)
            distance = (extra[0] << 8) + extra[1] + 1
        else:
            count = ((byte & 0x3F) >> 2) + 3
            extra = src.read(1)
            distance = ((byte & 0x03) << 8) + extra[0] + 1

        if distance > len(dst):
            raise ValueError("Invalid match distance")

        if count <= distance:
            dst += dst[-distance : (-distance + count) or None]
        else:
            # The match overlaps the output it produces, so it repeats the last distance bytes
            chunk = dst[-distance:]
            dst += chunk * (count // distance)
            dst += chunk[: count % distance]

    return bytes(dst)
