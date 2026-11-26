"""LZXPRESS Huffman compression and decompression.

This is the LZ77+Huffman algorithm of [MS-XCA]. Every 65536 bytes of data are compressed as a block with its own
Huffman table.

References:
    - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-frs2/8cb5bae9-edf3-4833-9f0a-9d7e24218d3d
    - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/a8b7cb0a-92a6-4187-a23b-5e14273b96f8
"""

from __future__ import annotations

import io
import struct
from collections import defaultdict, deque
from typing import BinaryIO

from dissect.util.compression.huffman import HuffmanDecoder, HuffmanEncoder
from dissect.util.stream import BitStream

_H = struct.Struct("<H")
_I = struct.Struct("<I")

BLOCK_SIZE = 65536
MIN_MATCH = 3
WINDOW = 65535
CHAIN_LIMIT = 128
END_OF_STREAM = 256


class _BitWriter:
    """Bit stream writer for 16-bit little endian words, with bytes in between.

    Like the reader, the writer keeps two words ahead of the bytes, so that bytes end up after the words that the
    reader has buffered at that point.
    """

    def __init__(self, dst: bytearray):
        self.dst = dst
        self.offsets = [len(dst), len(dst) + 2]
        self.dst += bytes(4)

        self.buffer = 0
        self.free = 16

    def write(self, n: int, value: int) -> None:
        if self.free >= n:
            self.buffer = (self.buffer << n) | value
            self.free -= n
        else:
            # Complete the current word with the high bits, the low bits start the next word
            self.buffer = (self.buffer << self.free) | (value >> (n - self.free))
            _H.pack_into(self.dst, self.offsets[0], self.buffer & 0xFFFF)
            self.offsets = [self.offsets[1], len(self.dst)]
            self.dst += bytes(2)

            self.buffer = value
            self.free += 16 - n

    def flush(self) -> None:
        _H.pack_into(self.dst, self.offsets[0], (self.buffer << self.free) & 0xFFFF)


def _build_decoder(buf: bytes) -> HuffmanDecoder:
    if len(buf) != 256:
        raise ValueError("Not enough data for Huffman code tree")

    lengths = []
    for c in buf:
        lengths.append(c & 0x0F)
        lengths.append((c >> 4) & 0x0F)

    # The codes must fill the whole code space, so unlike in some other formats a single code isn't allowed
    if len(lengths) - lengths.count(0) < 2:
        raise ValueError("Invalid Huffman tree")

    decoder = HuffmanDecoder(512, 15)
    decoder.import_lengths(lengths)
    return decoder


def compress(src: bytes | BinaryIO) -> bytes:
    """LZXPRESS Huffman compress from a file-like object or bytes.

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
    offset = 0

    # Every block decompresses to 65536 bytes and has its own Huffman table, the last block ends with the end-of-stream
    # symbol, so there is always at least one block
    end_of_stream = False
    while not end_of_stream:
        block_end = min(offset + BLOCK_SIZE, len(data))
        symbols = []
        counts = [0] * 512

        while offset < block_end:
            length = 0
            distance = 0

            for match_offset in reversed(chains.get(data[offset : offset + MIN_MATCH], ())):
                if offset - match_offset > WINDOW:
                    break

                match_length = MIN_MATCH
                while (
                    offset + match_length < block_end
                    and data[match_offset + match_length] == data[offset + match_length]
                ):
                    match_length += 1

                if match_length > length:
                    length = match_length
                    distance = offset - match_offset

            # The symbol of a match of 3 bytes at distance 1 is also the end-of-stream symbol, so avoid it
            if length == 0 or (length == MIN_MATCH and distance == 1):
                # Literal
                symbol = data[offset]
                length = 1
            else:
                # Match
                symbol = 256 + ((distance.bit_length() - 1) << 4) + min(length - MIN_MATCH, 15)

            symbols.append((symbol, length, distance))
            counts[symbol] += 1

            for i in range(offset, offset + length):
                chains[data[i : i + MIN_MATCH]].append(i)
            offset += length

        if end_of_stream := offset == len(data):
            counts[END_OF_STREAM] += 1

        # A complete Huffman tree needs at least two symbols
        if counts.count(0) > len(counts) - 2:
            counts[counts.index(0)] = 1

        encoder = HuffmanEncoder(512, 15)
        encoder.import_counts(counts)

        for i in range(0, 512, 2):
            dst.append(encoder.lengths[i] | (encoder.lengths[i + 1] << 4))

        writer = _BitWriter(dst)
        for symbol, length, distance in symbols:
            writer.write(encoder.lengths[symbol], encoder.codes[symbol])
            if symbol < 256:
                continue

            # The length is extended with a byte and a word, matches don't reach past the block for a dword
            length -= MIN_MATCH
            if length >= 15:
                if length - 15 < 255:
                    dst.append(length - 15)
                else:
                    dst.append(255)
                    dst += _H.pack(length)

            distance_bits = distance.bit_length() - 1
            writer.write(distance_bits, distance - (1 << distance_bits))

        if end_of_stream:
            writer.write(encoder.lengths[END_OF_STREAM], encoder.codes[END_OF_STREAM])
        writer.flush()

    return bytes(dst)


def decompress(src: bytes | BinaryIO, size: int | None = None) -> bytes:
    """LZXPRESS Huffman decompress from a file-like object or bytes.

    Decompresses until the decompressed size is reached or, if it's not given, until the end-of-stream symbol.

    The end-of-stream symbol is also a valid match symbol, so without a decompressed size it's only recognized as such
    when nothing but zero bits follow it. Pass the decompressed size whenever it's known.

    Args:
        src: File-like object or bytes to decompress.
        size: The decompressed size, if known.

    Returns:
        The decompressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    dst = bytearray()

    start_offset = src.tell()
    src.seek(0, io.SEEK_END)
    end_offset = src.tell()
    src.seek(start_offset, io.SEEK_SET)

    while end_offset - src.tell() >= 256 and (size is None or len(dst) < size):
        decoder = _build_decoder(src.read(256))

        # The reference decoder keeps at least 16 bits buffered after every removal
        # The extra length bytes and the next block are read directly after these buffered bits, so we do the same
        stream = BitStream(src, word_size=2, byteorder="little")
        stream.ensure(16)

        # Matches can extend past the end of a block, which extends the block
        block_end = len(dst) + BLOCK_SIZE
        if size is not None:
            block_end = min(block_end, size)

        # The last 16 bits of the input are only ever buffered, decoding them means that the input is truncated
        while len(dst) < block_end and stream.bits >= 16:
            symbol = decoder.decode(stream)
            stream.ensure(16)

            if symbol < 256:
                dst.append(symbol)
                continue

            if symbol == END_OF_STREAM and size is None and src.tell() >= end_offset and not stream.buffer:
                # End-of-stream symbol, the input is fully read and only zero bits remain
                return bytes(dst)

            symbol -= 256
            length = symbol & 0x0F
            symbol >>= 4

            offset = (1 << symbol) + stream.read(symbol)

            if length == 15:
                try:
                    length = stream.read_bytes(1)[0] + 15

                    if length == 270:
                        length = _H.unpack(stream.read_bytes(2))[0]

                        if length == 0:
                            length = _I.unpack(stream.read_bytes(4))[0]
                except (IndexError, struct.error):
                    raise ValueError("Truncated LZXpress Huffman stream") from None

                if length < 15:
                    raise ValueError("Invalid match length")

            stream.ensure(16)

            length += MIN_MATCH

            if offset > len(dst):
                raise ValueError("Invalid match distance")

            if size is not None:
                # Only the part up to the decompressed size is needed
                length = min(length, size - len(dst))

            if length <= offset:
                dst += dst[-offset : (-offset + length) or None]
            else:
                # The match overlaps the output it produces, so it repeats the last offset bytes
                chunk = dst[-offset:]
                dst += chunk * (length // offset)
                dst += chunk[: length % offset]

        if stream.bits < 16:
            raise ValueError("Truncated LZXpress Huffman stream")

    if size is not None and len(dst) < size:
        raise ValueError("Truncated LZXpress Huffman stream")

    return bytes(dst)
