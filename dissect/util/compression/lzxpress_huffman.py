"""LZXPRESS Huffman compression and decompression per [MS-XCA] S2.1-2.2."""

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-frs2/8cb5bae9-edf3-4833-9f0a-9d7e24218d3d
# https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-XCA/[MS-XCA].pdf
from __future__ import annotations

import io
import struct
from collections import Counter
from typing import BinaryIO, NamedTuple


class Symbol(NamedTuple):
    """Huffman symbol with its code length."""

    length: int
    symbol: int


def _read_16_bit(fh: BinaryIO) -> int:
    return struct.unpack("<H", fh.read(2).rjust(2, b"\x00"))[0]


class Node:
    """Huffman tree node."""

    __slots__ = ("children", "is_leaf", "symbol")

    def __init__(self, symbol: Symbol | None = None, is_leaf: bool = False):
        self.symbol = symbol
        self.is_leaf = is_leaf
        self.children = [None, None]


def _add_leaf(nodes: list[Node], idx: int, mask: int, bits: int) -> int:
    node = nodes[0]
    i = idx + 1

    while bits > 1:
        bits -= 1
        childidx = (mask >> bits) & 1
        if node.children[childidx] is None:
            node.children[childidx] = nodes[i]
            nodes[i].is_leaf = False
            i += 1
        node = node.children[childidx]

    node.children[mask & 1] = nodes[idx]
    return i


def _build_tree(buf: bytes) -> Node:
    if len(buf) != 256:
        raise ValueError("Not enough data for Huffman code tree")

    nodes = [Node() for _ in range(1024)]
    symbols: list[Symbol] = []

    for i, c in enumerate(buf):
        symbols.append(Symbol(c & 0x0F, i * 2))
        symbols.append(Symbol((c >> 4) & 0x0F, i * 2 + 1))

    symbols = sorted(symbols)

    symbol_index_start = 0
    for s in symbols:
        if s.length > 0:
            break
        symbol_index_start += 1

    mask = 0
    bits = 1

    root = nodes[0]

    tree_index = 1
    for symbol_index in range(symbol_index_start, 512):
        s = symbols[symbol_index]

        node = nodes[tree_index]
        node.symbol = s.symbol
        node.is_leaf = True

        mask = (mask << s.length - bits) & 0xFFFFFFFF
        bits = s.length

        tree_index = _add_leaf(nodes, tree_index, mask, bits)
        mask += 1

    return root


class BitString:
    """LSB-first bitstream reader for LZXPRESS Huffman decoding."""

    def __init__(self):
        self.source = None
        self.mask = 0
        self.bits = 0

    @property
    def index(self) -> int:
        """Current byte offset in the source stream."""
        return self.source.tell()

    def init(self, fh: BinaryIO) -> None:
        """Initialize the bitstream from a file-like object."""
        self.mask = (_read_16_bit(fh) << 16) + _read_16_bit(fh)
        self.bits = 32
        self.source = fh

    def read(self, n: int) -> bytes:
        """Read n raw bytes from the underlying stream."""
        return self.source.read(n)

    def lookup(self, n: int) -> int:
        """Peek at the top n bits without consuming them."""
        if n == 0:
            return 0

        return self.mask >> (32 - n)

    def skip(self, n: int) -> None:
        """Consume n bits and refill from the stream."""
        self.mask = (self.mask << n) & 0xFFFFFFFF
        self.bits -= n
        if self.bits < 16:
            self.mask += _read_16_bit(self.source) << (16 - self.bits)
            self.bits += 16

    def decode(self, root: Node) -> Symbol:
        """Decode one Huffman symbol from the bitstream."""
        node = root
        while not node.is_leaf:
            bit = self.lookup(1)
            self.skip(1)
            node = node.children[bit]
        return node.symbol


def decompress(src: bytes | BinaryIO, max_size: int | None = None) -> bytes:
    """LZXPRESS decompress from a file-like object or bytes.

    Decompresses until EOF of the input data.

    Args:
        src: File-like object or bytes to decompress.
        max_size: Optional maximum output size in bytes. When set, raises
            ValueError if the decompressed output would exceed this limit.

    Returns:
        The decompressed data.

    Raises:
        ValueError: If the output exceeds ``max_size``, the Huffman table is
            truncated, or the stream contains an invalid match length.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    dst = bytearray()

    start_offset = src.tell()
    src.seek(0, io.SEEK_END)
    size = src.tell() - start_offset
    src.seek(start_offset, io.SEEK_SET)

    bitstring = BitString()

    while src.tell() - start_offset < size:
        root = _build_tree(src.read(256))
        bitstring.init(src)

        chunk_size = 0
        while chunk_size < 65536:
            symbol = bitstring.decode(root)
            if symbol < 256:
                if max_size is not None and len(dst) >= max_size:
                    raise ValueError(f"decoded output would exceed the {max_size}-byte limit")
                dst.append(symbol)
                chunk_size += 1
            elif symbol == 256:
                return bytes(dst)
            else:
                symbol -= 256
                length = symbol & 0x0F
                symbol >>= 4

                offset = (1 << symbol) + bitstring.lookup(symbol)

                if length == 15:
                    length = ord(bitstring.read(1)) + 15

                    if length == 270:
                        length = _read_16_bit(bitstring.source)
                        if length == 0:
                            length = struct.unpack("<I", bitstring.read(4))[0]
                        elif length < 15:
                            raise ValueError("wrong match length")

                bitstring.skip(symbol)

                length += 3

                if max_size is not None and len(dst) + length > max_size:
                    raise ValueError(f"decoded output would exceed the {max_size}-byte limit")

                remaining = length
                while remaining > 0:
                    match_size = min(remaining, offset)
                    dst += dst[-offset : (-offset + match_size) or None]
                    remaining -= match_size

                chunk_size += length

    return bytes(dst)


# --- Compress ([MS-XCA] S2.1) ---

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
