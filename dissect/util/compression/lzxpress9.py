"""XPRESS9 compression and decompression.

XPRESS9 combines LZ77 with Huffman coding, ESE databases can use it for compressed data. It has no public
specification, this follows the decoder of the ESE C codec.

References:
    - https://github.com/microsoft/Extensible-Storage-Engine/tree/main/dev/ese/src/_xpress9
"""

from __future__ import annotations

import io
import struct
from collections import defaultdict, deque
from typing import BinaryIO, NamedTuple

from dissect.util.compression.huffman import HuffmanDecoder, HuffmanEncoder
from dissect.util.hash import crc32c

MAGIC = 0x4E86D72A

MAX_CODE_LENGTH = 27
SHORT_SYMBOLS = 256 + (28 << 4)
LONG_SYMBOLS = 256
LONG_LENGTH_SYMBOLS = 232

# The code lengths of a Huffman table are mostly encoded as is, or with one of these symbols
FILL = 28
ZERO_REPEAT = 29
PREVIOUS = 30
ROW = 31
ROW_PLUS_ONE = 32

MIN_MATCH = 3
# The longest length that the long length table and its extra bits can encode is a bit over this
MAX_MATCH = 1 << 24
WINDOW = 65536
CHAIN_LIMIT = 128


class _BitStream:
    """Bit stream reader for a block, reading the least significant bit first.

    Reading past the end of the block returns zero bits, as long as no more than 4 bytes are buffered beyond it.
    """

    def __init__(self, buf: bytes):
        self.buf = buf
        self.offset = 0

        self.buffer = 0
        self.bits = 0

    def tell(self) -> int:
        return self.offset * 8 - self.bits

    def peek(self, n: int) -> int:
        while self.bits < n:
            # Bits that are only needed past the end of the block mean the block has been read past its size
            if self.offset >= len(self.buf) + 4:
                raise ValueError("Invalid XPRESS9 block size")

            self.buffer |= int.from_bytes(self.buf[self.offset : self.offset + 4], "little") << self.bits
            self.bits += 32
            self.offset += 4

        return self.buffer & ((1 << n) - 1)

    def remove(self, n: int) -> None:
        self.buffer >>= n
        self.bits -= n

    def read(self, n: int) -> int:
        value = self.peek(n)
        self.remove(n)
        return value


class _BitWriter:
    """Bit stream writer for a block, writing the least significant bit first."""

    def __init__(self):
        self.dst = bytearray()

        self.buffer = 0
        self.bits = 0

    def tell(self) -> int:
        return len(self.dst) * 8 + self.bits

    def write(self, n: int, value: int) -> None:
        self.buffer |= value << self.bits
        self.bits += n

        while self.bits >= 8:
            self.dst.append(self.buffer & 0xFF)
            self.buffer >>= 8
            self.bits -= 8

    def flush(self) -> None:
        if self.bits:
            self.dst.append(self.buffer)


class _BlockHeader(NamedTuple):
    __struct__ = struct.Struct("<8I")

    magic: int
    size: int
    num_bits: int
    flags: int
    reserved: int
    session: int
    index: int
    # CRC-32C of the fields above
    checksum: int


def _read_header(src: BinaryIO) -> _BlockHeader | None:
    if not (buf := src.read(32)):
        return None

    if len(buf) != 32:
        raise ValueError("Truncated XPRESS9 block header")

    header = _BlockHeader._make(_BlockHeader.__struct__.unpack(buf))
    if header.magic != MAGIC:
        raise ValueError("Invalid XPRESS9 block magic")

    if header.reserved != 0 or header.flags >> 20:
        raise ValueError("Invalid XPRESS9 block header")

    if crc32c.crc32c(buf[:28]) != header.checksum:
        raise ValueError("Invalid XPRESS9 block header checksum")

    # An MTF count of 6 is reserved
    if (header.flags >> 16) & 3 == 3:
        raise ValueError("Invalid XPRESS9 MTF count")

    if header.num_bits <= 256 + (header.flags & 0x1FFF):
        raise ValueError("Invalid XPRESS9 block size")

    return header


def _read_huffman(stream: _BitStream, num_codes: int) -> HuffmanDecoder:
    if (encoding := stream.read(3)) == 0:
        # Stored, the first symbols use one bit less than the others
        bits = num_codes.bit_length() - 1
        count = (2 << bits) - num_codes
        lengths = [bits] * count + [bits + 1] * (num_codes - count)
    elif encoding == 1:
        # Huffman coded, using a small Huffman table of which the code lengths are stored relative to the previous one
        small_lengths = []
        length = 4
        for _ in range(33):
            if stream.read(1):
                if (value := stream.read(3)) >= length:
                    value += 1
                length = value
            small_lengths.append(length)

        decoder = HuffmanDecoder(33, 8, lsb_first=True)
        decoder.import_lengths(small_lengths)

        lengths = []
        previous = 8
        while len(lengths) < num_codes:
            if (symbol := decoder.decode(stream)) <= MAX_CODE_LENGTH:
                lengths.append(symbol)
                if symbol:
                    previous = symbol

            elif symbol == FILL:
                # Zeros up to the next multiple of 16 symbols
                lengths.extend([0] * (16 - len(lengths) % 16))

            elif symbol == ZERO_REPEAT:
                count = stream.read(2) + 5
                if count == 8:
                    while (value := stream.read(3)) == 7:
                        count += 7
                    count += value

                # The zeros stay within a row of 16 symbols, only a fill reaches the end of it
                if len(lengths) % 16 + count >= 16:
                    raise ValueError("Invalid XPRESS9 Huffman table")

                lengths.extend([0] * count)

            elif symbol == PREVIOUS:
                lengths.append(previous)

            else:
                # The code length of the symbol 16 symbols back, possibly plus one
                if len(lengths) < 16 or not 0 < (previous := lengths[-16] + symbol - ROW) <= MAX_CODE_LENGTH:
                    raise ValueError("Invalid XPRESS9 Huffman table")

                lengths.append(previous)
    else:
        raise ValueError("Invalid XPRESS9 Huffman table encoding")

    # The reference decoder doesn't accept a table without any codes
    if not any(lengths):
        raise ValueError("Invalid XPRESS9 Huffman table")

    decoder = HuffmanDecoder(num_codes, max(lengths), lsb_first=True)
    decoder.import_lengths(lengths)
    return decoder


def _write_huffman(writer: _BitWriter, encoder: HuffmanEncoder) -> None:
    # Huffman coded, without the symbols that repeat code lengths
    small_counts = [0] * 33
    for length in encoder.lengths:
        small_counts[length] += 1

    small_encoder = HuffmanEncoder(33, 8, lsb_first=True)
    small_encoder.import_counts(small_counts)

    writer.write(3, 1)

    previous = 4
    for length in small_encoder.lengths:
        if length == previous:
            writer.write(1, 0)
        else:
            writer.write(1, 1)
            writer.write(3, length - 1 if length > previous else length)
            previous = length

    for length in encoder.lengths:
        writer.write(small_encoder.lengths[length], small_encoder.codes[length])


def compress(src: bytes | BinaryIO) -> bytes:
    """XPRESS9 compress from a file-like object or bytes.

    Produces a single block without MTF offsets, using a minimum match length of 3 and a window of 64 KiB.

    Args:
        src: File-like object or bytes to compress.

    Returns:
        The compressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    if not (data := src.read()):
        return b""

    symbols = []
    short_counts = [0] * SHORT_SYMBOLS
    long_counts = [0] * LONG_SYMBOLS

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
                match_length < MAX_MATCH
                and offset + match_length < len(data)
                and data[match_offset + match_length] == data[offset + match_length]
            ):
                match_length += 1

            if match_length > length:
                length = match_length
                distance = offset - match_offset

        symbol = data[offset]
        long_symbol = None
        extra_bits = []

        if length == 0:
            # Literal
            length = 1
        else:
            # Match, a long length continues with a symbol of the long length table, the longest also with extra bits
            if (long_length := length - MIN_MATCH - 15) >= LONG_LENGTH_SYMBOLS:
                long_value = long_length - LONG_LENGTH_SYMBOLS + 1
                long_bits = long_value.bit_length() - 1
                long_symbol = LONG_LENGTH_SYMBOLS + long_bits
                extra_bits.append((long_bits, long_value - (1 << long_bits)))
            elif long_length >= 0:
                long_symbol = long_length

            distance_bits = distance.bit_length() - 1
            extra_bits.append((distance_bits, distance - (1 << distance_bits)))
            symbol = 256 + (distance_bits << 4) + min(length - MIN_MATCH, 15)

        symbols.append((symbol, long_symbol, extra_bits))
        short_counts[symbol] += 1
        if long_symbol is not None:
            long_counts[long_symbol] += 1

        for i in range(offset, offset + length):
            chains[data[i : i + MIN_MATCH]].append(i)
        offset += length

    # The reference decoder doesn't accept a table without any codes
    if not any(long_counts):
        long_counts[0] = 1

    short_encoder = HuffmanEncoder(SHORT_SYMBOLS, MAX_CODE_LENGTH, lsb_first=True)
    short_encoder.import_counts(short_counts)
    long_encoder = HuffmanEncoder(LONG_SYMBOLS, MAX_CODE_LENGTH, lsb_first=True)
    long_encoder.import_counts(long_counts)

    writer = _BitWriter()
    _write_huffman(writer, short_encoder)
    _write_huffman(writer, long_encoder)
    table_bits = writer.tell()

    for symbol, long_symbol, extra_bits in symbols:
        writer.write(short_encoder.lengths[symbol], short_encoder.codes[symbol])
        if long_symbol is not None:
            writer.write(long_encoder.lengths[long_symbol], long_encoder.codes[long_symbol])
        for n, value in extra_bits:
            writer.write(n, value)

    num_bits = 256 + writer.tell()
    writer.flush()

    fields = (MAGIC, len(data), num_bits, table_bits, 0, 0, 0)
    checksum = crc32c.crc32c(_BlockHeader.__struct__.pack(*fields, 0)[:28])
    return _BlockHeader.__struct__.pack(*fields, checksum) + writer.dst


def decompress(src: bytes | BinaryIO) -> bytes:
    """XPRESS9 decompress from a file-like object or bytes.

    The data consists of one or more blocks, which together form a session.

    Args:
        src: File-like object or bytes to decompress.

    Returns:
        The decompressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    dst = bytearray()
    num_blocks = 0
    first = None

    while header := _read_header(src):
        # The blocks of a session are numbered, and share the session signature and the parameters in the flags
        first = first or header
        if header.index != num_blocks or header.session != first.session or header.flags >> 13 != first.flags >> 13:
            raise ValueError("Invalid XPRESS9 block sequence")

        # The flags hold the size of the Huffman tables in bits, the window size, the number of MTF offsets, and the
        # minimum lengths of a match with a regular offset and a match with an MTF offset
        table_bits = header.flags & 0x1FFF
        window_bits = ((header.flags >> 13) & 7) + 16
        mtf_count = ((header.flags >> 16) & 3) * 2
        min_match = ((header.flags >> 18) & 1) + 3
        mtf_min_match = ((header.flags >> 19) & 1) + 2

        # The number of bits includes the header
        num_bytes = (header.num_bits + 7) // 8 - 32
        if len(buf := src.read(num_bytes)) != num_bytes:
            raise ValueError("Truncated XPRESS9 block")

        stream = _BitStream(buf)

        # MTF offsets, the most recently used offsets
        last_was_match = 0
        mtf = []
        if mtf_count:
            last_was_match = stream.read(1)
            for _ in range(mtf_count):
                if (bits := stream.read(5)) >= window_bits:
                    raise ValueError("Invalid XPRESS9 MTF offset")
                mtf.append(stream.read(bits) + (1 << bits))

        short_decoder = _read_huffman(stream, SHORT_SYMBOLS)
        long_decoder = _read_huffman(stream, LONG_SYMBOLS)
        if stream.tell() != table_bits:
            raise ValueError("Invalid XPRESS9 Huffman table size")

        block_end = len(dst) + header.size
        while len(dst) < block_end:
            if (symbol := short_decoder.decode(stream)) < 256:
                dst.append(symbol)
                last_was_match = 0
                continue

            symbol -= 256
            length = symbol & 0x0F
            symbol >>= 4

            if length == 15:
                if (length := long_decoder.decode(stream)) >= LONG_LENGTH_SYMBOLS:
                    bits = length - LONG_LENGTH_SYMBOLS
                    length = stream.read(bits) + (1 << bits) + LONG_LENGTH_SYMBOLS - 1
                length += 15

            if symbol < mtf_count:
                length += mtf_min_match

                if last_was_match:
                    # A match can't directly follow a match with the same offset, so the first MTF offset is skipped
                    if symbol == mtf_count - 1:
                        raise ValueError("Invalid XPRESS9 MTF offset")
                    symbol += 1

                offset = mtf.pop(symbol)
                mtf.insert(0, offset)
            else:
                length += min_match

                bits = symbol - mtf_count
                offset = stream.read(bits) + (1 << bits)
                if mtf:
                    mtf.pop()
                    mtf.insert(0, offset)

            last_was_match = 1

            if offset > len(dst):
                raise ValueError("Invalid match distance")

            if len(dst) + length > block_end:
                raise ValueError("Invalid match length")

            if length <= offset:
                dst += dst[-offset : (-offset + length) or None]
            else:
                # The match overlaps the output it produces, so it repeats the last offset bytes
                chunk = dst[-offset:]
                dst += chunk * (length // offset)
                dst += chunk[: length % offset]

        if 256 + stream.tell() != header.num_bits:
            raise ValueError("Invalid XPRESS9 block size")

        num_blocks += 1

    return bytes(dst)


def decompressed_size(src: bytes | BinaryIO) -> int:
    """Get the decompressed size of XPRESS9 data from its block headers, without decompressing it.

    Args:
        src: File-like object or bytes of the compressed data.

    Returns:
        The decompressed size.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    total = 0
    while header := _read_header(src):
        total += header.size
        src.seek((header.num_bits + 7) // 8 - 32, io.SEEK_CUR)

    return total
