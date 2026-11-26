"""LZNT1 compression and decompression.

LZNT1 is the LZ77-type compression that NTFS uses for compressed files. Every 4096 bytes of data are compressed
separately as a chunk.

References:
    - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/a8b7cb0a-92a6-4187-a23b-5e14273b96f8
    - https://github.com/google/rekall/blob/master/rekall-core/rekall/plugins/filesystems/lznt1.py
"""

from __future__ import annotations

import array
import io
import struct
from collections import defaultdict, deque
from typing import BinaryIO

_H = struct.Struct("<H")


def _get_displacement(offset: int) -> int:
    """Calculate the displacement."""
    result = 0
    while offset >= 0x10:
        offset >>= 1
        result += 1

    return result


DISPLACEMENT_TABLE = array.array("B", [_get_displacement(x) for x in range(8192)])

COMPRESSED_MASK = 1 << 15
SIGNATURE_MASK = 3 << 12
SIZE_MASK = (1 << 12) - 1
TAG_MASKS = [(1 << i) for i in range(8)]

CHUNK_SIZE = 4096
MIN_MATCH = 3
CHAIN_LIMIT = 128


def compress(src: bytes | BinaryIO) -> bytes:
    """LZNT1 compress from a file-like object or bytes.

    Args:
        src: File-like object or bytes to compress.

    Returns:
        The compressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    dst = bytearray()

    # Every chunk is compressed on its own, so matches can't refer back into a previous chunk
    while chunk := src.read(CHUNK_SIZE):
        block = bytearray()
        chains = defaultdict(lambda: deque(maxlen=CHAIN_LIMIT))
        header_offset = 0
        header_bit = 8
        offset = 0

        while offset < len(chunk):
            if header_bit == 8:
                header_offset = len(block)
                block.append(0)
                header_bit = 0

            # The further into the chunk, the more bits are used for the displacement and the fewer for the length,
            # there are always enough to reach back to the start of the chunk
            displacement = DISPLACEMENT_TABLE[offset - 1] if offset else 0
            max_length = (0xFFF >> displacement) + MIN_MATCH

            length = 0
            distance = 0

            for match_offset in reversed(chains.get(chunk[offset : offset + MIN_MATCH], ())):
                match_length = MIN_MATCH
                while (
                    match_length < max_length
                    and offset + match_length < len(chunk)
                    and chunk[match_offset + match_length] == chunk[offset + match_length]
                ):
                    match_length += 1

                if match_length > length:
                    length = match_length
                    distance = offset - match_offset

            if length == 0:
                # Literal
                block.append(chunk[offset])
                length = 1
            else:
                # Match
                block[header_offset] |= TAG_MASKS[header_bit]
                block += _H.pack(((distance - 1) << (12 - displacement)) | (length - MIN_MATCH))

            header_bit += 1

            for i in range(offset, offset + length):
                chains[chunk[i : i + MIN_MATCH]].append(i)
            offset += length

        if len(block) < len(chunk):
            dst += _H.pack(COMPRESSED_MASK | SIGNATURE_MASK | (len(block) - 1))
            dst += block
        else:
            # Store the chunk uncompressed if compressing doesn't make it smaller
            dst += _H.pack(SIGNATURE_MASK | (len(chunk) - 1))
            dst += chunk

    return bytes(dst)


def decompress(src: bytes | BinaryIO) -> bytes:
    """LZNT1 decompress from a file-like object or bytes.

    Args:
        src: File-like object or bytes to decompress.

    Returns:
        The decompressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    dst = bytearray()
    chunk_offset = 0

    # A zero header marks the end of the data, it's left out if it doesn't fit in the buffer
    while len(buf := src.read(2)) == 2 and (block_header := _H.unpack(buf)[0]) != 0:
        if block_header & SIGNATURE_MASK != SIGNATURE_MASK:
            raise ValueError("Invalid LZNT1 chunk signature")

        hsize = (block_header & SIZE_MASK) + 1
        if len(block := src.read(hsize)) != hsize:
            raise ValueError("Truncated LZNT1 chunk")

        # Every chunk except the last decompresses to CHUNK_SIZE bytes, like Linux and ntfs-3g a shorter chunk is
        # padded with zeros
        dst += bytes(chunk_offset - len(dst))

        if not block_header & COMPRESSED_MASK:
            dst += block
            chunk_offset += CHUNK_SIZE
            continue

        i = 0
        while i < hsize:
            header = block[i]
            i += 1

            for mask in TAG_MASKS:
                if i >= hsize:
                    break

                if not header & mask:
                    dst.append(block[i])
                    i += 1
                    continue

                if i + 2 > hsize:
                    raise ValueError("Invalid LZNT1 chunk")

                pointer = _H.unpack_from(block, i)[0]
                i += 2

                position = len(dst) - chunk_offset
                displacement = DISPLACEMENT_TABLE[position - 1]

                symbol_offset = (pointer >> (12 - displacement)) + 1
                symbol_length = (pointer & (0xFFF >> displacement)) + MIN_MATCH

                # Matches can't refer back into a previous chunk, so a chunk also can't start with a match
                if symbol_offset > position:
                    raise ValueError("Invalid match distance")

                if symbol_length <= symbol_offset:
                    dst += dst[-symbol_offset : (-symbol_offset + symbol_length) or None]
                else:
                    # The match overlaps the output it produces, so it repeats the last symbol_offset bytes
                    chunk = dst[-symbol_offset:]
                    dst += chunk * (symbol_length // symbol_offset)
                    dst += chunk[: symbol_length % symbol_offset]

            if len(dst) - chunk_offset > CHUNK_SIZE:
                raise ValueError("Invalid LZNT1 chunk")

        chunk_offset += CHUNK_SIZE

    return bytes(dst)
