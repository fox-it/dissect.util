"""LZNT1 compression and decompression per [MS-XCA] S2.5."""

# Reference: https://github.com/google/rekall/blob/master/rekall-core/rekall/plugins/filesystems/lznt1.py
from __future__ import annotations

import array
import io
import struct
from typing import BinaryIO


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


def decompress(src: bytes | BinaryIO) -> bytes:
    """LZNT1 decompress from a file-like object or bytes.

    Args:
        src: File-like object or bytes to decompress.

    Returns:
        The decompressed data.

    Raises:
        struct.error: If the input is truncated or malformed.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    offset = src.tell()
    src.seek(0, io.SEEK_END)
    size = src.tell() - offset
    src.seek(offset)

    dst = io.BytesIO()

    while src.tell() - offset < size:
        block_offset = src.tell()
        uncompressed_chunk_offset = dst.tell()

        block_header = struct.unpack("<H", src.read(2))[0]
        if block_header & SIGNATURE_MASK != SIGNATURE_MASK:
            break

        hsize = block_header & SIZE_MASK

        block_end = block_offset + hsize + 3

        if block_header & COMPRESSED_MASK:
            while src.tell() < block_end:
                header = ord(src.read(1))
                for mask in TAG_MASKS:
                    if src.tell() >= block_end:
                        break

                    if header & mask:
                        pointer = struct.unpack("<H", src.read(2))[0]
                        displacement = DISPLACEMENT_TABLE[dst.tell() - uncompressed_chunk_offset - 1]

                        symbol_offset = (pointer >> (12 - displacement)) + 1
                        symbol_length = (pointer & (0xFFF >> displacement)) + 3

                        dst.seek(-symbol_offset, io.SEEK_END)
                        data = dst.read(symbol_length)

                        # Pad the data to make it fit.
                        if 0 < len(data) < symbol_length:
                            data = data * (symbol_length // len(data) + 1)
                            data = data[:symbol_length]

                        dst.seek(0, io.SEEK_END)
                        dst.write(data)
                    else:
                        data = src.read(1)
                        dst.write(data)

        else:
            # Block is not compressed
            data = src.read(hsize + 1)
            dst.write(data)

    return dst.getvalue()


# --- Compression helpers ([MS-XCA] S2.5.2-2.5.4) ---

_CHUNK_SIZE = 4096
"""Uncompressed bytes consumed per chunk; [MS-XCA] S2.5.3 mandates 4096-byte units."""

_MIN_MATCH = 3
"""Minimum match length; stored length is actual minus 3 ([MS-XCA] S2.5.1.4)."""

_MAX_MATCH_CANDIDATES = 256
"""Encoder-only cap on hash-chain probes per position; bounds worst-case time."""


def _displacement_bits(pos: int) -> int:
    """Return the displacement bit width at a chunk position per [MS-XCA] section 2.5.1.4.

    Reuses the module-level DISPLACEMENT_TABLE, adding the minimum D of 4 that the
    table's values are relative to.
    """
    if pos == 0:
        return 4
    return DISPLACEMENT_TABLE[pos - 1] + 4


def _find_match(chunk: bytes, pos: int, table: dict[bytes, list[int]]) -> tuple[int, int]:
    """Return (length, displacement) of the best match at pos, or (0, 0) if none.

    Searches the hash chain in reverse (most recent first) for the longest match
    within the displacement window allowed by the current chunk position.
    """
    if len(chunk) - pos < _MIN_MATCH:
        return 0, 0

    disp_bits = _displacement_bits(pos)
    max_displacement = min(pos, 1 << disp_bits)
    max_length = min(len(chunk) - pos, (1 << (16 - disp_bits)) - 1 + _MIN_MATCH)

    best_length = 0
    best_displacement = 0

    candidates = table.get(chunk[pos : pos + _MIN_MATCH], [])
    for candidate in reversed(candidates[-_MAX_MATCH_CANDIDATES:]):
        if pos - candidate > max_displacement:
            break
        length = _MIN_MATCH
        while length < max_length and chunk[candidate + length] == chunk[pos + length]:
            length += 1
        if length > best_length:
            best_length = length
            best_displacement = pos - candidate
            if length == max_length:
                break

    return best_length, best_displacement


def _compress_chunk(chunk: bytes) -> bytes:
    """Encode one chunk of plaintext into an LZNT1 flag-group body.

    Each flag group is a flag byte followed by up to eight data elements. A clear
    flag bit emits a literal byte; a set bit emits a 16-bit compressed word encoding
    a (displacement, length) back-reference per [MS-XCA] section 2.5.1.3.
    """
    body = bytearray()
    table: dict[bytes, list[int]] = {}
    group_flags = 0
    group_items = bytearray()
    group_count = 0
    pos = 0

    while pos < len(chunk):
        length, displacement = _find_match(chunk, pos, table)

        if length >= _MIN_MATCH:
            disp_bits = _displacement_bits(pos)
            word = (displacement - 1) << (16 - disp_bits) | (length - _MIN_MATCH)
            group_items += struct.pack("<H", word)
            group_flags |= 1 << group_count
        else:
            length = 1
            group_items.append(chunk[pos])

        for indexed in range(pos, min(pos + length, len(chunk) - _MIN_MATCH + 1)):
            table.setdefault(chunk[indexed : indexed + _MIN_MATCH], []).append(indexed)

        pos += length
        group_count += 1

        if group_count == 8:
            body.append(group_flags)
            body += group_items
            group_flags = 0
            group_items.clear()
            group_count = 0

    if group_count:
        body.append(group_flags)
        body += group_items

    return bytes(body)


def compress(src: bytes | BinaryIO) -> bytes:
    """LZNT1 compress from a file-like object or bytes.

    Consumes the input in 4096-byte units per [MS-XCA] section 2.5.3, emitting one
    chunk each: a compressed chunk when the flag-group body is smaller than the raw
    data, otherwise an uncompressed chunk.

    Args:
        src: File-like object or bytes to compress.

    Returns:
        The compressed data.
    """
    if hasattr(src, "read"):
        src = src.read()

    result = bytearray()

    for start in range(0, len(src), _CHUNK_SIZE):
        chunk = src[start : start + _CHUNK_SIZE]
        body = _compress_chunk(chunk)

        if len(body) < len(chunk):
            header = COMPRESSED_MASK | SIGNATURE_MASK | (len(body) + 2 - 3)
            result += struct.pack("<H", header)
            result += body
        else:
            header = SIGNATURE_MASK | (len(chunk) + 2 - 3)
            result += struct.pack("<H", header)
            result += chunk

    return bytes(result)
