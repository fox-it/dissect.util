"""LZXPRESS compression and decompression.

This is the Plain LZ77 algorithm of [MS-XCA]. ESE databases can use it for compressed data.

References:
    - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/a8b7cb0a-92a6-4187-a23b-5e14273b96f8
"""

from __future__ import annotations

import io
import struct
from collections import defaultdict, deque
from typing import BinaryIO

_H = struct.Struct("<H")
_I = struct.Struct("<I")

MIN_MATCH = 3
WINDOW = 8192
CHAIN_LIMIT = 128


def compress(src: bytes | BinaryIO) -> bytes:
    """LZXPRESS compress from a file-like object or bytes.

    Args:
        src: File-like object or bytes to compress.

    Returns:
        The compressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    data = src.read()
    dst = bytearray(4)

    flags = 0
    flags_count = 0
    flags_offset = 0
    last_length_half_byte = 0

    chains = defaultdict(lambda: deque(maxlen=CHAIN_LIMIT))
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
            # Literal
            dst.append(data[offset])
            flags <<= 1
            length = 1
        else:
            # Match, the length is extended with a nibble (shared by two matches), a byte, a word and a dword
            match_length = length - MIN_MATCH
            dst += _H.pack(((distance - 1) << 3) | min(match_length, 7))

            if match_length >= 7:
                nibble = min(match_length - 7, 15)
                if last_length_half_byte == 0:
                    last_length_half_byte = len(dst)
                    dst.append(nibble)
                else:
                    dst[last_length_half_byte] |= nibble << 4
                    last_length_half_byte = 0

            if match_length >= 15 + 7:
                if match_length < 255 + 15 + 7:
                    dst.append(match_length - 15 - 7)
                else:
                    dst.append(255)
                    if match_length < 1 << 16:
                        dst += _H.pack(match_length)
                    else:
                        dst += _H.pack(0) + _I.pack(match_length)

            flags = (flags << 1) | 1

        flags_count += 1
        if flags_count == 32:
            _I.pack_into(dst, flags_offset, flags)
            flags = 0
            flags_count = 0
            flags_offset = len(dst)
            dst += bytes(4)

        for i in range(offset, offset + length):
            chains[data[i : i + MIN_MATCH]].append(i)
        offset += length

    # The unused flags are set, a match flag at the end of the input ends the stream
    flags = (flags << (32 - flags_count)) | ((1 << (32 - flags_count)) - 1)
    _I.pack_into(dst, flags_offset, flags)

    return bytes(dst)


def decompress(src: bytes | BinaryIO, size: int | None = None) -> bytes:
    """LZXPRESS decompress from a file-like object or bytes.

    Decompresses until the end of the input or, if it's given, until the decompressed size is reached.

    Args:
        src: File-like object or bytes to decompress.
        size: The decompressed size, if known.

    Returns:
        The decompressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    offset = src.tell()
    src.seek(0, io.SEEK_END)
    src_size = src.tell() - offset
    src.seek(offset)

    dst = bytearray()

    buffered_flags = 0
    buffered_flags_count = 0
    last_length_half_byte = 0

    try:
        while src.tell() - offset < src_size and (size is None or len(dst) < size):
            if buffered_flags_count == 0:
                buffered_flags = _I.unpack(src.read(4))[0]
                buffered_flags_count = 32

            buffered_flags_count -= 1
            if buffered_flags & (1 << buffered_flags_count) == 0:
                dst.append(src.read(1)[0])
            else:
                if src.tell() - offset == src_size:
                    break

                match = _H.unpack(src.read(2))[0]
                match_offset, match_length = divmod(match, 8)
                match_offset += 1

                if match_length == 7:
                    if last_length_half_byte == 0:
                        last_length_half_byte = src.tell()
                        match_length = src.read(1)[0] % 16
                    else:
                        rewind = src.tell()
                        src.seek(last_length_half_byte)
                        match_length = src.read(1)[0] // 16
                        src.seek(rewind)
                        last_length_half_byte = 0

                    if match_length == 15:
                        match_length = src.read(1)[0]
                        if match_length == 255:
                            match_length = _H.unpack(src.read(2))[0]
                            if match_length == 0:
                                match_length = _I.unpack(src.read(4))[0]

                            if match_length < 15 + 7:
                                raise ValueError("wrong match length")

                            match_length -= 15 + 7
                        match_length += 15
                    match_length += 7
                match_length += 3

                if match_offset > len(dst):
                    raise ValueError("Invalid match distance")

                if size is not None:
                    # Only the part up to the decompressed size is needed, so a corrupt length can't use a lot of memory
                    match_length = min(match_length, size - len(dst))

                if match_length <= match_offset:
                    dst += dst[-match_offset : (-match_offset + match_length) or None]
                else:
                    # The match overlaps the output it produces, so it repeats the last match_offset bytes
                    chunk = dst[-match_offset:]
                    dst += chunk * (match_length // match_offset)
                    dst += chunk[: match_length % match_offset]
    except (IndexError, struct.error):
        raise ValueError("Truncated LZXpress stream") from None

    return bytes(dst)
