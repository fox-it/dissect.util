# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-frs2/8cb5bae9-edf3-4833-9f0a-9d7e24218d3d
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/a8b7cb0a-92a6-4187-a23b-5e14273b96f8
from __future__ import annotations

import io
from collections import Counter
from typing import BinaryIO

from dissect.util.compression.huffman import HuffmanDecoder
from dissect.util.stream import BitStream


def _build_decoder(buf: bytes) -> HuffmanDecoder:
    if len(buf) != 256:
        raise ValueError("Not enough data for Huffman code tree")

    lengths = []
    for c in buf:
        lengths.append(c & 0x0F)
        lengths.append((c >> 4) & 0x0F)

    decoder = HuffmanDecoder(512, 15)
    decoder.import_lengths(lengths)
    return decoder


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
        block_end = len(dst) + 65536
        if size is not None:
            block_end = min(block_end, size)

        while len(dst) < block_end and stream.bits:
            symbol = decoder.decode(stream)
            stream.ensure(16)

            if symbol < 256:
                dst.append(symbol)
                continue

            if symbol == 256 and size is None and src.tell() >= end_offset and not stream.buffer:
                # End-of-stream symbol, the input is fully read and only zero bits remain
                return bytes(dst)

            symbol -= 256
            length = symbol & 0x0F
            symbol >>= 4

            offset = (1 << symbol) + stream.read(symbol)

            if length == 15:
                length = ord(stream.read_bytes(1)) + 15

                if length == 270:
                    length = int.from_bytes(stream.read_bytes(2), "little")

                    if length == 0:
                        length = int.from_bytes(stream.read_bytes(4), "little")

            stream.ensure(16)

            length += 3

            if offset > len(dst):
                raise ValueError("Invalid match distance")

            if length <= offset:
                dst += dst[-offset : (-offset + length) or None]
            else:
                # The match overlaps the output it produces, so it repeats the last offset bytes
                chunk = dst[-offset:]
                dst += chunk * (length // offset)
                dst += chunk[: length % offset]

    return bytes(dst[:size])


# Compression ([MS-XCA] 2.1)

_BLOCK_SIZE = 65536
_TABLE_SIZE = 256
_SYMBOL_COUNT = 512
_EOF_SYMBOL = 256
_MIN_MATCH = 3
_MAX_CODE_LENGTH = 15
_MAX_OFFSET = 65535
_MAX_CHAIN = 64
_LEN_BYTE_MAX = 0xFF
_LEN_U16_LIMIT = 0x10000
_MIN_SYMBOLS = 2

_Token = tuple[str, int, int]


def _high_bit(value: int) -> int:
    """Return the index of the highest set bit (GetHighBit, [MS-XCA] S2.1.4.1)."""
    return value.bit_length() - 1


def _match_symbol(length: int, distance: int) -> int:
    """Return the Huffman symbol for a match (256-511), per [MS-XCA] S2.1.4.1."""
    return _EOF_SYMBOL + min(length - _MIN_MATCH, _MAX_CODE_LENGTH) + 16 * _high_bit(distance)


def _lz77(data: bytes) -> list[_Token]:
    """Greedy LZ77 factorization with a 3-byte hash chain ([MS-XCA] S2.1.4.1)."""
    tokens: list[_Token] = []
    heads: dict[int, int] = {}
    chain: list[int] = [-1] * len(data)
    n = len(data)
    pos = 0
    while pos < n:
        best_len = 0
        best_dist = 0
        if pos + _MIN_MATCH <= n:
            key = (data[pos] << 16) | (data[pos + 1] << 8) | data[pos + 2]
            candidate = heads.get(key, -1)
            depth = 0
            while candidate >= 0 and depth < _MAX_CHAIN:
                distance = pos - candidate
                if distance > _MAX_OFFSET:
                    break
                length = 0
                limit = n - pos
                while length < limit and data[candidate + length] == data[pos + length]:
                    length += 1
                if length > best_len:
                    best_len = length
                    best_dist = distance
                candidate = chain[candidate]
                depth += 1
        if best_len >= _MIN_MATCH and _match_symbol(best_len, best_dist) > _EOF_SYMBOL:
            tokens.append(("M", best_len, best_dist))
            advance = best_len
        else:
            tokens.append(("L", data[pos], 0))
            advance = 1
        end = pos + advance
        while pos < end and pos + _MIN_MATCH <= n:
            key = (data[pos] << 16) | (data[pos + 1] << 8) | data[pos + 2]
            chain[pos] = heads.get(key, -1)
            heads[key] = pos
            pos += 1
        pos = end
    return tokens


def _limited_lengths(freqs: Counter[int]) -> dict[int, int]:
    """Compute canonical Huffman code lengths capped at 15 bits via package-merge."""
    items = sorted((count, symbol) for symbol, count in freqs.items())
    n = len(items)
    lengths = {symbol: 0 for _, symbol in items}
    if n == 1:
        lengths[items[0][1]] = 1
        return lengths
    base = sorted((items[i][0], (i,)) for i in range(n))
    current = list(base)
    for _ in range(_MAX_CODE_LENGTH - 1):
        packaged = [
            (current[j][0] + current[j + 1][0], current[j][1] + current[j + 1][1])
            for j in range(0, len(current) - 1, 2)
        ]
        current = sorted(base + packaged)
    counts = [0] * n
    for _weight, indices in current[: 2 * n - 2]:
        for i in indices:
            counts[i] += 1
    for i in range(n):
        lengths[items[i][1]] = counts[i]
    return lengths


def _canonical_codes(lengths: dict[int, int]) -> dict[int, int]:
    """Assign canonical Huffman codes from bit lengths ([MS-XCA] S2.2.4 ordering)."""
    ordered = sorted(symbol for symbol, length in lengths.items() if length > 0)
    ordered.sort(key=lambda symbol: (lengths[symbol], symbol))
    codes: dict[int, int] = {}
    code = 0
    prev_length = 0
    for symbol in ordered:
        code <<= lengths[symbol] - prev_length
        codes[symbol] = code
        code += 1
        prev_length = lengths[symbol]
    return codes


def _pack_table(lengths: dict[int, int]) -> bytearray:
    """Pack 512 bit lengths into the 256-byte table ([MS-XCA] S2.1.4.3)."""
    table = bytearray(_TABLE_SIZE)
    for symbol, length in lengths.items():
        if symbol % 2 == 0:
            table[symbol // 2] |= length & 0x0F
        else:
            table[symbol // 2] |= (length & 0x0F) << 4
    return table


class _BitWriter:
    """Output engine: 16-bit words with two deferred slots ([MS-XCA] S2.1.4.3)."""

    __slots__ = ("buf", "free", "pos", "pos1", "pos2", "word")

    def __init__(self, table: bytearray) -> None:
        self.buf = bytearray(table)
        self.buf += b"\x00\x00\x00\x00"
        self.pos1 = _TABLE_SIZE
        self.pos2 = _TABLE_SIZE + 2
        self.pos = _TABLE_SIZE + 4
        self.free = 16
        self.word = 0

    def _emit_word(self) -> None:
        """Write the completed 16-bit word to pos1 and rotate."""
        self.buf[self.pos1] = self.word & 0xFF
        self.buf[self.pos1 + 1] = (self.word >> 8) & 0xFF
        self.pos1 = self.pos2
        self.pos2 = self.pos
        self.buf += b"\x00\x00"
        self.pos += 2

    def write_bits(self, count: int, bits: int) -> None:
        """Append count bits (MSB-first) to the deferred bit stream."""
        if count == 0:
            return
        if self.free >= count:
            self.free -= count
            self.word = (self.word << count) + bits
        else:
            self.word = (self.word << self.free) + (bits >> (count - self.free))
            self.free -= count
            self._emit_word()
            self.free += 16
            self.word = bits

    def write_byte(self, value: int) -> None:
        """Write a raw extra-length byte at the current cursor."""
        self.buf.append(value & 0xFF)
        self.pos += 1

    def write_u16(self, value: int) -> None:
        """Write a raw little-endian uint16 extra-length value."""
        self.buf += value.to_bytes(2, "little")
        self.pos += 2

    def write_u32(self, value: int) -> None:
        """Write a raw little-endian uint32 extra-length value (v10.0 escape)."""
        self.buf += value.to_bytes(4, "little")
        self.pos += 4

    def finish(self) -> bytes:
        """Flush the pending bits and a trailing zero word."""
        self.word <<= self.free
        self.buf[self.pos1] = self.word & 0xFF
        self.buf[self.pos1 + 1] = (self.word >> 8) & 0xFF
        self.buf[self.pos2] = 0
        self.buf[self.pos2 + 1] = 0
        return bytes(self.buf[: self.pos])


def _write_length_extra(writer: _BitWriter, length: int) -> None:
    """Emit extra bytes past the 4-bit match-length nibble ([MS-XCA] S2.1.4.3)."""
    value = length - _MIN_MATCH
    if value < _MAX_CODE_LENGTH:
        return
    value -= _MAX_CODE_LENGTH
    if value < _LEN_BYTE_MAX:
        writer.write_byte(value)
        return
    writer.write_byte(_LEN_BYTE_MAX)
    value += _MAX_CODE_LENGTH
    if value < _LEN_U16_LIMIT:
        writer.write_u16(value)
    else:
        writer.write_u16(0)
        writer.write_u32(value)


def _encode_block(tokens: list[_Token], *, is_last: bool) -> bytes:
    """Huffman-encode one block's tokens into a table + bit stream ([MS-XCA] S2.1)."""
    freqs: Counter[int] = Counter()
    for token in tokens:
        if token[0] == "L":
            freqs[token[1]] += 1
        else:
            freqs[_match_symbol(token[1], token[2])] += 1
    if is_last:
        freqs[_EOF_SYMBOL] += 1
    filler = 0
    while len(freqs) < _MIN_SYMBOLS:
        if filler not in freqs:
            freqs[filler] = 1
        filler += 1
    lengths = _limited_lengths(freqs)
    codes = _canonical_codes(lengths)
    writer = _BitWriter(_pack_table(lengths))
    for token in tokens:
        if token[0] == "L":
            writer.write_bits(lengths[token[1]], codes[token[1]])
            continue
        length, distance = token[1], token[2]
        symbol = _match_symbol(length, distance)
        writer.write_bits(lengths[symbol], codes[symbol])
        _write_length_extra(writer, length)
        high = _high_bit(distance)
        writer.write_bits(high, distance - (1 << high))
    if is_last:
        writer.write_bits(lengths[_EOF_SYMBOL], codes[_EOF_SYMBOL])
    return writer.finish()


def compress(src: bytes | BinaryIO) -> bytes:
    """LZXPRESS Huffman compress from a file-like object or bytes.

    Runs a greedy LZ77 pass, segments the tokens into 64 KiB output blocks each
    with its own canonical Huffman table, and appends the EOF symbol after the
    final block. Per [MS-XCA] S2.1.

    Args:
        src: File-like object or bytes to compress.

    Returns:
        The compressed data.
    """
    if hasattr(src, "read"):
        src = src.read()

    data = bytes(src)
    tokens = _lz77(data)
    out = bytearray()
    index = 0
    produced = 0
    count = len(tokens)
    while True:
        block: list[_Token] = []
        base = produced
        while index < count and produced < base + _BLOCK_SIZE:
            token = tokens[index]
            block.append(token)
            produced += 1 if token[0] == "L" else token[1]
            index += 1
        is_last = index >= count
        out += _encode_block(block, is_last=is_last)
        if is_last:
            break
    return bytes(out)
