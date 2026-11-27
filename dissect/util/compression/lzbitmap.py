"""LZBITMAP compression and decompression.

LZBITMAP is an Apple compression that APFS can use for compressed files. It has no public specification.

References:
    - https://github.com/eafer/libzbitmap
    - https://github.com/sgan81/apfs-fuse
"""

from __future__ import annotations

import io
import itertools
import struct
from collections import Counter, defaultdict, deque
from typing import BinaryIO

_H = struct.Struct("<H")

MAGIC = b"ZBM\x09"
CHUNK_SIZE = 0x8000
MIN_MATCH = 3
WINDOW = 0xFFFF
CHAIN_LIMIT = 128

# Bitmaps 0 to 2 are read from the bitmap area, 3 to 14 are the most common bitmaps in the table at the end of the
# chunk, and 15 marks a repeat count
TABLE_BASE = 3
TABLE_SIZE = 12


def compress(src: bytes | BinaryIO) -> bytes:
    """LZBITMAP compress from a file-like object or bytes.

    Args:
        src: File-like object or bytes to compress.

    Returns:
        The compressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    data = src.read()
    dst = bytearray(MAGIC)

    chains = defaultdict(lambda: deque(maxlen=CHAIN_LIMIT))

    for chunk_offset in range(0, len(data), CHUNK_SIZE):
        chunk_end = min(chunk_offset + CHUNK_SIZE, len(data))

        literals = bytearray()
        distances = bytearray()
        groups = []

        # Every 8 bytes have a bitmap of which bytes are literals, the other bytes are copied from a distance back
        distance = 8
        for offset in range(chunk_offset, chunk_end, 8):
            size = min(8, chunk_end - offset)

            # Without a match all bytes are literals, a match costs a byte for every literal and 1 or 2 bytes for a new
            # distance
            best_bitmap = (1 << size) - 1
            best_distance = distance
            best_cost = size

            candidates = [distance] if distance <= offset else []
            for match_offset in reversed(chains.get(data[offset : offset + MIN_MATCH], ())):
                if offset - match_offset > WINDOW:
                    break
                candidates.append(offset - match_offset)

            for candidate in candidates:
                bitmap = 0
                for i in range(size):
                    if data[offset + i] != data[offset + i - candidate]:
                        bitmap |= 1 << i

                cost = bitmap.bit_count() + (0 if candidate == distance else 1 if candidate <= 0xFF else 2)
                if cost < best_cost:
                    best_bitmap = bitmap
                    best_distance = candidate
                    best_cost = cost

                    # A cheaper bitmap isn't possible
                    if cost == 0:
                        break

            if best_distance == distance:
                distance_size = 0
            elif best_distance <= 0xFF:
                distance_size = 1
                distances.append(best_distance)
            else:
                distance_size = 2
                distances += _H.pack(best_distance)
            distance = best_distance

            groups.append((best_bitmap, distance_size))
            literals += bytes(data[offset + i] for i in range(size) if best_bitmap & (1 << i))

            for i in range(offset, offset + size):
                chains[data[i : i + MIN_MATCH]].append(i)

        # The most common bitmaps are in the table, the others are in the bitmap area
        table = [group for group, _ in Counter(groups).most_common(TABLE_SIZE)]
        bitmaps = bytes(group[0] for group in groups if group not in table)

        # Bitmaps from the bitmap area are numbered by the size of their distance
        numbers = [table.index(group) + TABLE_BASE if group in table else group[1] for group in groups]

        nibbles = []
        for number, run in itertools.groupby(numbers):
            count = len(list(run))
            nibbles.append(number)
            if count < 4:
                nibbles += [number] * (count - 1)
            else:
                # A repeat count is a 0xF followed by nibbles of which the sum is the count minus 4, ending at the first
                # nibble that isn't 0xF
                nibbles += [0xF] * (1 + (count - 4) // 15) + [(count - 4) % 15]
        if len(nibbles) % 2:
            nibbles.append(0)
        tokens = bytes(low | (high << 4) for low, high in zip(nibbles[0::2], nibbles[1::2], strict=True))

        bits = 0
        for i, (bitmap, distance_size) in enumerate(table):
            bits |= (bitmap | (distance_size << 8)) << (10 * i)

        chunk = data[chunk_offset:chunk_end]
        distance_offset = 15 + len(literals)
        bitmap_offset = distance_offset + len(distances)
        token_offset = bitmap_offset + len(bitmaps)
        compressed_size = token_offset + len(tokens) + 17

        if compressed_size < len(chunk) + 6:
            dst += compressed_size.to_bytes(3, "little")
            dst += len(chunk).to_bytes(3, "little")
            dst += distance_offset.to_bytes(3, "little")
            dst += bitmap_offset.to_bytes(3, "little")
            dst += token_offset.to_bytes(3, "little")
            dst += literals + distances + bitmaps + tokens + bits.to_bytes(17, "little")
        else:
            # Store the chunk uncompressed if compressing doesn't make it smaller, a chunk of the same size would be
            # mistaken for one
            dst += (len(chunk) + 6).to_bytes(3, "little")
            dst += len(chunk).to_bytes(3, "little")
            dst += chunk

    # A chunk without data marks the end of the stream
    dst += (6).to_bytes(3, "little") + bytes(3)

    return bytes(dst)


def decompress(src: bytes | BinaryIO) -> bytes:
    """LZBITMAP decompress from a file-like object or bytes.

    Decompresses until EOF or EOS of the input data.

    Args:
        src: File-like object or bytes to decompress.

    Returns:
        The decompressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    if src.read(4) != MAGIC:
        raise ValueError("Not a valid LZBITMAP stream")

    dst = bytearray()

    while True:
        compressed_size = int.from_bytes(src.read(3), "little")
        uncompressed_size = int.from_bytes(src.read(3), "little")

        if uncompressed_size == 0:
            # End of stream
            break

        if compressed_size == uncompressed_size + 6:  # chunk header size
            # Not compressed
            dst += src.read(uncompressed_size)

        else:
            # Compressed
            distance_offset = int.from_bytes(src.read(3), "little")
            bitmap_offset = int.from_bytes(src.read(3), "little")
            token_offset = int.from_bytes(src.read(3), "little")
            literal_offset = 15

            # Buffer the whole chunk
            src.seek(-15, io.SEEK_CUR)
            buf = memoryview(src.read(compressed_size))

            # Build the bitmap/token map
            token_map = []
            bits = int.from_bytes(buf[-17:], "little")
            for i in range(0xF):
                if i < 3:
                    token_map.append((None, i))
                else:
                    token_map.append((bits & 0xFF, (bits >> 8) & 3))
                    bits >>= 10

            # Tokens are stored as nibbles, so we need to split each byte into two
            tokens = itertools.chain.from_iterable((b & 0xF, (b >> 4) & 0xF) for b in buf[token_offset:-17])

            # Initial match distance is 8, and is not reset between tokens
            distance = 8

            prev_token = None
            while uncompressed_size > 0:
                if (idx := next(tokens, None) if prev_token is None else prev_token) is None:
                    break

                if idx == 0xF:
                    # 0xF indicates a repeat count
                    raise ValueError("Invalid token index in LZBITMAP stream")

                if uncompressed_size <= 8:
                    # The last bitmap has no repeat count, a nibble after it is padding
                    repeat = 1
                elif (repeat := next(tokens)) != 0xF:
                    # No repeat count, store the token for next iteration
                    prev_token = repeat
                    repeat = 1
                else:
                    # Repeat count, read and sum
                    prev_token = None
                    total = 4
                    while repeat == 0xF:
                        repeat = next(tokens)
                        total += repeat

                        if total < repeat:
                            raise ValueError("Invalid repeat count in LZBITMAP stream")

                    repeat = total

                for _ in range(repeat):
                    # Like libzbitmap, repeats past the end of the chunk are ignored
                    if uncompressed_size == 0:
                        break

                    bitmap, token = token_map[idx]
                    if idx < 3:
                        # Index 0, 1, 2 are special and indicate we need to read a bitmap from the bitmap region
                        bitmap = buf[bitmap_offset]
                        bitmap_offset += 1

                    if token == 1:
                        # 1-byte distance
                        distance = buf[distance_offset]
                        distance_offset += 1
                    elif token == 2:
                        # 2-byte distance
                        (distance,) = _H.unpack_from(buf, distance_offset)
                        distance_offset += 2

                    for _ in range(8):
                        if bitmap & 1:
                            # Literal
                            dst.append(buf[literal_offset])
                            literal_offset += 1
                        else:
                            # Match
                            if distance > len(dst):
                                raise ValueError("Invalid match distance in LZBITMAP stream")
                            dst.append(dst[-distance])

                        bitmap >>= 1
                        uncompressed_size -= 1
                        if uncompressed_size == 0:
                            break

    return bytes(dst)
