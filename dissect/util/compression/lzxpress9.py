"""XPRESS9 compression and decompression.

Implements the compressor and decompressor for the XPRESS9 format used by ESE
(Extensible Storage Engine) databases. XPRESS9 is an LZ77+Huffman codec with
multi-table Huffman coding, move-to-front repeated offsets, and Elias-gamma
length escaping. It has no public byte-format specification; the authority
is the MIT-licensed ESE C codec in ``dev/ese/src/_xpress9/``.

The on-disk layout consists of one or more blocks, each starting with a 32-byte
header (magic ``0x4E86D72A``, CRC-32C protected) followed by an LSB-first
bitstream holding: optional MTF initial state, two serialized canonical-Huffman
code-length tables (short-symbol alphabet of 704, long-length alphabet of 256),
and the LZ77 token stream with Elias-gamma offset coding.

Reference implementation: ntcompress (https://github.com/StrongWind1/ntcompress).
"""

from __future__ import annotations

import struct
from typing import Final

from dissect.util.exceptions import CorruptDataError
from dissect.util.hash import crc32c as _crc32c_mod

_crc32c = _crc32c_mod.crc32c

# --- Block format constants (Xpress9Internal.h) ---

BLOCK_HEADER_SIZE: Final = 32
"""Size of ``LZ77_BLOCK_HEADER``: 8 x u32 LE (Xpress9Internal.h:972-984)."""

_XPRESS9_MAGIC: Final = 0x4E86D72A
"""``XPRESS9_MAGIC``, word [0] of every block header (Xpress9Internal.h:970)."""

_MAX_SHORT_LENGTH_LOG: Final = 4
_MAX_SHORT_LENGTH: Final = 1 << _MAX_SHORT_LENGTH_LOG
_MAX_WINDOW_SIZE_LOG: Final = 24
_MAX_MTF: Final = 4
_LONG_LENGTH_ALPHABET_SIZE: Final = 256
_MAX_LONG_LENGTH: Final = _LONG_LENGTH_ALPHABET_SIZE - _MAX_WINDOW_SIZE_LOG
_SHORT_SYMBOL_ALPHABET_SIZE: Final = 256 + ((_MAX_WINDOW_SIZE_LOG + _MAX_MTF) << _MAX_SHORT_LENGTH_LOG)
_MAX_CODEWORD_LENGTH: Final = 27

# Code-length table opcodes (Xpress9Internal.h:604-611).
_TABLE_FILL: Final = _MAX_CODEWORD_LENGTH + 1
_TABLE_ZERO_REPT: Final = _MAX_CODEWORD_LENGTH + 2
_TABLE_PREV: Final = _MAX_CODEWORD_LENGTH + 3
_TABLE_ROW_0: Final = _MAX_CODEWORD_LENGTH + 4
_TABLE_ROW_1: Final = _MAX_CODEWORD_LENGTH + 5
_TABLE_ALPHABET_SIZE: Final = _MAX_CODEWORD_LENGTH + 6
_TABLE_ZERO_REPT_MIN_COUNT: Final = 5
_TABLE_FILL_BOUNDARY: Final = 16

_TABLE_ENCODING_STORED: Final = 0
_TABLE_ENCODING_HUFFMAN: Final = 1
_SMALL_TABLE_MAX_LENGTH: Final = 8
_SMALL_TABLE_INITIAL_PREV: Final = 4
_MAIN_TABLE_INITIAL_PREV: Final = 8
_ZERO_REPT_EXTEND: Final = 3
_ZERO_REPT_CONTINUE: Final = 7

_BLOCK_HEADER: Final = struct.Struct("<8I")

_FLAGS_HUFFMAN_TABLE_BITS_MASK: Final = 0x1FFF
_FLAGS_RESERVED_SHIFT: Final = 20

_MAX_DECODED_SIZE: Final = 1 << 30

# --- Bit input ---


class _BitReader:
    """LSB-first bit reader over one block's payload bitstream.

    Port of ``BIORD_*`` (Xpress9Internal.h:390-472).
    """

    __slots__ = ("_acc", "_data", "_navail", "_pos", "_size")

    _OVERRUN_BYTES: Final = 8

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._size = len(data)
        self._pos = 0
        self._acc = 0
        self._navail = 0

    @property
    def bits_consumed(self) -> int:
        """Bits consumed so far."""
        return (self._pos << 3) - self._navail

    def read(self, count: int) -> int:
        """Return the next ``count`` bits as an integer, LSB first."""
        while self._navail < count:
            if self._pos < self._size:
                self._acc |= self._data[self._pos] << self._navail
            elif self._pos >= self._size + self._OVERRUN_BYTES:
                raise CorruptDataError("XPRESS9 bitstream exhausted")
            self._pos += 1
            self._navail += 8
        value = self._acc & ((1 << count) - 1)
        self._acc >>= count
        self._navail -= count
        return value


# --- Canonical Huffman ---


class _CanonicalHuffman:
    """Canonical-Huffman decoder built from a code-length table.

    Equivalent to ``HuffmanCreateDecodeTables`` + ``HUFFMAN_DECODE_SYMBOL``
    (Xpress9DecHuffman.c:154-321).
    """

    __slots__ = ("_base_index", "_counts", "_first_code", "_max_length", "_single", "_symbols")

    def __init__(self, lengths: list[int]) -> None:
        present = sorted((length, symbol) for symbol, length in enumerate(lengths) if length)
        if not present:
            raise CorruptDataError("XPRESS9 Huffman code-length table has no symbols")

        self._max_length = present[-1][0]
        self._single: tuple[int, int] | None = None
        if len(present) == 1:
            self._single = (present[0][1], present[0][0])
            self._counts, self._first_code, self._base_index, self._symbols = [], [], [], []
            return

        counts = [0] * (self._max_length + 1)
        for length, _ in present:
            counts[length] += 1

        nodes = 0
        for length in range(self._max_length, 0, -1):
            nodes += counts[length]
            if nodes & 1:
                raise CorruptDataError(f"XPRESS9 Huffman code lengths do not form a full tree at depth {length}")
            nodes >>= 1
        if nodes != 1:
            raise CorruptDataError("XPRESS9 Huffman code lengths do not form a full tree")

        first_code = [0] * (self._max_length + 1)
        base_index = [0] * (self._max_length + 1)
        code = 0
        index = 0
        for length in range(1, self._max_length + 1):
            first_code[length] = code
            base_index[length] = index
            code = (code + counts[length]) << 1
            index += counts[length]

        self._counts = counts
        self._first_code = first_code
        self._base_index = base_index
        self._symbols = [symbol for _, symbol in present]

    def decode(self, reader: _BitReader) -> int:
        """Decode one symbol from the stream."""
        if self._single is not None:
            symbol, skip = self._single
            reader.read(skip)
            return symbol

        code = 0
        for length in range(1, self._max_length + 1):
            code = (code << 1) | reader.read(1)
            delta = code - self._first_code[length]
            if delta < self._counts[length]:
                return self._symbols[self._base_index[length] + delta]

        raise CorruptDataError("XPRESS9 Huffman codeword exceeds the table's maximum length")


# --- Code-length table decoding ---


def _decode_zero_run(reader: _BitReader, position: int, alphabet_size: int, fill_boundary: int) -> int:
    """Read a zero-run length (Xpress9DecHuffman.c:541-564)."""
    count = reader.read(2)
    run = count + _TABLE_ZERO_REPT_MIN_COUNT
    if count == _ZERO_REPT_EXTEND:
        while True:
            count = reader.read(3)
            run += count
            if position + run > alphabet_size or (position ^ (position + run)) >= fill_boundary:
                raise CorruptDataError(f"XPRESS9 zero run of {run} at index {position} overflows")
            if count != _ZERO_REPT_CONTINUE:
                break
    if position + run > alphabet_size or (position ^ (position + run)) >= fill_boundary:
        raise CorruptDataError(f"XPRESS9 zero run of {run} at index {position} overflows")
    return run


def _decode_small_table(reader: _BitReader) -> _CanonicalHuffman:
    """Read the 33-symbol small code that encodes the length table (Xpress9DecHuffman.c:462-508)."""
    prev = _SMALL_TABLE_INITIAL_PREV
    lengths: list[int] = []
    for _ in range(_TABLE_ALPHABET_SIZE):
        if reader.read(1) == 0:
            lengths.append(prev)
            continue
        value = reader.read(3)
        if value >= prev:
            value += 1
            if value > _SMALL_TABLE_MAX_LENGTH:
                raise CorruptDataError(f"XPRESS9 small-table codeword length {value} exceeds {_SMALL_TABLE_MAX_LENGTH}")
        lengths.append(value)
        prev = value
    return _CanonicalHuffman(lengths)


def _apply_fill(lengths: list[int], position: int, fill_boundary: int) -> int:
    """Apply a fill opcode: zeros up to the next fill boundary (Xpress9DecHuffman.c:531-539)."""
    alphabet_size = len(lengths)
    while True:
        lengths[position] = 0
        position += 1
        if position & (fill_boundary - 1) == 0 or position >= alphabet_size:
            return position


def _apply_row(lengths: list[int], position: int, symbol: int, fill_boundary: int) -> int:
    """Apply a ROW_0/ROW_1 opcode: copy from one boundary back (Xpress9DecHuffman.c:581-613)."""
    if position < fill_boundary:
        raise CorruptDataError(f"XPRESS9 ROW opcode at index {position} has no previous row")
    value = lengths[position - fill_boundary] + (1 if symbol == _TABLE_ROW_1 else 0)
    if value == 0 or value > _MAX_CODEWORD_LENGTH:
        raise CorruptDataError(f"XPRESS9 ROW opcode yields invalid codeword length {value}")
    lengths[position] = value
    return value


def _decode_coded_lengths(reader: _BitReader, alphabet_size: int, fill_boundary: int) -> list[int]:
    """Read a mode-1 (Huffman-coded) code-length table (Xpress9DecHuffman.c:462-615)."""
    small = _decode_small_table(reader)
    lengths = [0] * alphabet_size
    prev = _MAIN_TABLE_INITIAL_PREV
    position = 0
    while position < alphabet_size:
        symbol = small.decode(reader)
        if symbol < _TABLE_FILL:
            lengths[position] = symbol
            position += 1
            if symbol:
                prev = symbol
        elif symbol == _TABLE_FILL:
            position = _apply_fill(lengths, position, fill_boundary)
        elif symbol == _TABLE_ZERO_REPT:
            position += _decode_zero_run(reader, position, alphabet_size, fill_boundary)
        elif symbol == _TABLE_PREV:
            lengths[position] = prev
            position += 1
        else:
            prev = _apply_row(lengths, position, symbol, fill_boundary)
            position += 1
    return lengths


def _decode_length_table(reader: _BitReader, alphabet_size: int, fill_boundary: int) -> list[int]:
    """Deserialize one canonical-Huffman code-length table (Xpress9DecHuffman.c:405-622)."""
    mode = reader.read(3)
    if mode == _TABLE_ENCODING_STORED:
        msb = alphabet_size.bit_length() - 1
        short_count = (1 << (msb + 1)) - alphabet_size
        return [msb] * short_count + [msb + 1] * (alphabet_size - short_count)
    if mode != _TABLE_ENCODING_HUFFMAN:
        raise CorruptDataError(f"XPRESS9 unknown table encoding {mode}")
    return _decode_coded_lengths(reader, alphabet_size, fill_boundary)


# --- Block header ---


def _parse_block_header(
    payload: bytes | memoryview, offset: int = 0
) -> tuple[int, int, int, int, int, int, int, int, int]:
    """Parse and validate a 32-byte block header (Xpress9DecLz77.c:607-716).

    Returns a tuple of:
        (orig_size, comp_size_bits, huffman_table_bits, window_size_log2,
         mtf_entry_count, ptr_min_match_length, mtf_min_match_length,
         session_signature, block_index)

    Raises:
        CorruptDataError: Truncated, bad magic, bad CRC, or invalid flags.
    """
    if len(payload) - offset < BLOCK_HEADER_SIZE:
        raise CorruptDataError(f"XPRESS9 block header truncated: need {BLOCK_HEADER_SIZE} bytes")

    words = _BLOCK_HEADER.unpack_from(payload, offset)

    if words[0] != _XPRESS9_MAGIC:
        raise CorruptDataError(f"Bad XPRESS9 block magic 0x{words[0]:08x}, expected 0x{_XPRESS9_MAGIC:08x}")
    if words[4] != 0:
        raise CorruptDataError(f"XPRESS9 block header reserved word is 0x{words[4]:08x}, must be 0")

    actual_crc = _crc32c(memoryview(payload)[offset : offset + BLOCK_HEADER_SIZE - 4])
    if words[7] != actual_crc:
        raise CorruptDataError(f"XPRESS9 block header CRC-32C mismatch: 0x{words[7]:08x} vs 0x{actual_crc:08x}")

    flags = words[3]
    if flags >> _FLAGS_RESERVED_SHIFT:
        raise CorruptDataError(f"XPRESS9 block flags reserved bits are non-zero: 0x{flags:08x}")

    mtf_entry_count = ((flags >> 16) & 3) << 1
    if mtf_entry_count > _MAX_MTF:
        raise CorruptDataError(f"XPRESS9 block declares reserved MTF entry count {mtf_entry_count}")

    huffman_table_bits = flags & _FLAGS_HUFFMAN_TABLE_BITS_MASK
    if words[2] <= huffman_table_bits + BLOCK_HEADER_SIZE * 8:
        raise CorruptDataError("XPRESS9 block compressed size does not exceed its header and Huffman tables")

    return (
        words[1],  # orig_size
        words[2],  # comp_size_bits
        huffman_table_bits,
        ((flags >> 13) & 7) + 16,  # window_size_log2
        mtf_entry_count,
        ((flags >> 18) & 1) + 3,  # ptr_min_match_length
        ((flags >> 19) & 1) + 2,  # mtf_min_match_length
        words[5],  # session_signature
        words[6],  # block_index
    )


# --- LZ77 token stream ---


def _read_mtf_initial_state(reader: _BitReader, mtf_count: int, window_log2: int) -> tuple[int, list[int]]:
    """Read the MTF seed: last-was-pointer flag and initial offsets (Xpress9DecLz77.c:362-383)."""
    last_was_ptr = reader.read(1)
    offsets: list[int] = []
    for _ in range(mtf_count):
        msb = reader.read(5)
        if msb >= window_log2:
            raise CorruptDataError(f"XPRESS9 MTF initial offset MSB {msb} outside {window_log2}-bit window")
        offsets.append(reader.read(msb) + (1 << msb))
    return last_was_ptr, offsets


def _take_mtf_offset(mtf: list[int], symbol: int, *, last_was_ptr: bool) -> int:
    """Pick and reorder the MTF list for one match (Xpress9Lz77Dec.i:143-220)."""
    if last_was_ptr:
        if symbol >= len(mtf) - 1:
            raise CorruptDataError(f"XPRESS9 MTF symbol {symbol} invalid after a pointer")
        offset = mtf.pop(symbol + 1)
        mtf.insert(0, offset)
        return offset
    offset = mtf[symbol]
    if symbol:
        del mtf[symbol]
        mtf.insert(0, offset)
    return offset


def _read_match_length(reader: _BitReader, long_table: _CanonicalHuffman) -> int:
    """Read an escaped match length from the long-length table (Xpress9Lz77Dec.i:128-141)."""
    length = long_table.decode(reader)
    if length >= _MAX_LONG_LENGTH:
        extra_bits = length - _MAX_LONG_LENGTH
        length = reader.read(extra_bits) + (1 << extra_bits) + (_MAX_LONG_LENGTH - 1)
    return length + _MAX_SHORT_LENGTH - 1


def _copy_match(out: bytearray, offset: int, length: int) -> None:
    """Append ``length`` bytes copied from ``offset`` bytes back, with overlap semantics."""
    start = len(out) - offset
    if length <= offset:
        out += out[start : start + length]
    else:
        repeats = -(-length // offset)
        out += (out[start:] * repeats)[:length]


def _read_block_prelude(
    reader: _BitReader,
    huffman_table_bits: int,
    mtf_entry_count: int,
    window_size_log2: int,
) -> tuple[int, list[int], _CanonicalHuffman, _CanonicalHuffman]:
    """Read MTF seed and both Huffman tables before the token stream (Xpress9DecLz77.c:346-442)."""
    last_was_ptr = 0
    mtf: list[int] = []
    if mtf_entry_count:
        last_was_ptr, mtf = _read_mtf_initial_state(reader, mtf_entry_count, window_size_log2)
    short_table = _CanonicalHuffman(_decode_length_table(reader, _SHORT_SYMBOL_ALPHABET_SIZE, _MAX_SHORT_LENGTH))
    long_table = _CanonicalHuffman(_decode_length_table(reader, _LONG_LENGTH_ALPHABET_SIZE, _MAX_SHORT_LENGTH))
    if reader.bits_consumed != huffman_table_bits:
        raise CorruptDataError(
            f"XPRESS9 Huffman tables consumed {reader.bits_consumed} bits, header declares {huffman_table_bits}"
        )
    return last_was_ptr, mtf, short_table, long_table


def _decode_block(
    reader: _BitReader,
    orig_size: int,
    comp_size_bits: int,
    huffman_table_bits: int,
    mtf_entry_count: int,
    ptr_min_match_length: int,
    mtf_min_match_length: int,
    window_size_log2: int,
    out: bytearray,
) -> None:
    """Decode one block's bitstream into ``out`` (Xpress9Lz77Dec.i:101-293)."""
    last_was_ptr, mtf, short_table, long_table = _read_block_prelude(
        reader, huffman_table_bits, mtf_entry_count, window_size_log2
    )
    target = len(out) + orig_size

    while len(out) < target:
        symbol = short_table.decode(reader)
        if symbol < 256:
            out.append(symbol)
            last_was_ptr = 0
            continue

        symbol -= 256
        length = symbol & (_MAX_SHORT_LENGTH - 1)
        symbol >>= _MAX_SHORT_LENGTH_LOG

        if length == _MAX_SHORT_LENGTH - 1:
            length = _read_match_length(reader, long_table)

        if symbol < mtf_entry_count:
            length += mtf_min_match_length
            offset = _take_mtf_offset(mtf, symbol, last_was_ptr=bool(last_was_ptr))
        else:
            length += ptr_min_match_length
            msb = symbol - mtf_entry_count
            offset = reader.read(msb) + (1 << msb)
            if mtf:
                mtf.insert(0, offset)
                mtf.pop()

        if offset > len(out):
            raise CorruptDataError(f"XPRESS9 match offset {offset} reaches before the start of data")
        if length > target - len(out):
            raise CorruptDataError(f"XPRESS9 match of length {length} overruns the block's declared size")

        last_was_ptr = 1
        _copy_match(out, offset, length)

    if len(out) != target:
        raise CorruptDataError(
            f"XPRESS9 block decoded {len(out) - target + orig_size} bytes, header declares {orig_size}"
        )
    actual_bits = reader.bits_consumed + BLOCK_HEADER_SIZE * 8
    if actual_bits != comp_size_bits:
        raise CorruptDataError(f"XPRESS9 block consumed {actual_bits} bits, header declares {comp_size_bits}")


# --- Session (block sequence) ---


def _session_blocks(payload: bytes) -> list[tuple[tuple[int, ...], int, int]]:
    """Split a codec payload into validated, byte-aligned blocks.

    Returns ``(header_fields, body_start, body_end)`` per block.

    Raises:
        CorruptDataError: Empty payload, truncated block, or header validation failure.
    """
    blocks: list[tuple[tuple[int, ...], int, int]] = []
    first: tuple[int, ...] | None = None
    offset = 0
    while offset < len(payload):
        header = _parse_block_header(payload, offset)
        if first is None:
            first = header
        elif header[7] != first[7]:
            raise CorruptDataError("XPRESS9 session signature mismatch between blocks")
        elif header[3:7] != first[3:7]:
            raise CorruptDataError("XPRESS9 block changes the session's coding parameters")
        if header[8] != len(blocks):
            raise CorruptDataError(f"XPRESS9 block index {header[8]}, expected {len(blocks)}")

        end = offset + ((header[1] + 7) >> 3)
        if end > len(payload):
            raise CorruptDataError(f"XPRESS9 block truncated: needs {end - offset} bytes")
        blocks.append((header, offset + BLOCK_HEADER_SIZE, end))
        offset = end

    if not blocks:
        raise CorruptDataError("XPRESS9 payload has no blocks")
    return blocks


def decompress(src: bytes) -> bytes:
    """Decompress raw XPRESS9 block data.

    Takes the codec payload (the bytes *after* any ESE record header) and
    returns the decompressed plaintext. The payload consists of one or more
    self-describing XPRESS9 blocks, each with a 32-byte header and a bitstream.

    Args:
        src: Raw XPRESS9 block data.

    Returns:
        The decompressed data.

    Raises:
        CorruptDataError: If the data is truncated, corrupt, or violates format invariants.
    """
    blocks = _session_blocks(src)
    declared_total = sum(h[0] for h, _, _ in blocks)
    if declared_total > _MAX_DECODED_SIZE:
        raise CorruptDataError(f"XPRESS9 declares {declared_total} bytes, over the safety limit")

    out = bytearray()
    for header, body_start, body_end in blocks:
        _decode_block(
            _BitReader(src[body_start:body_end]),
            header[0],  # orig_size
            header[1],  # comp_size_bits
            header[2],  # huffman_table_bits
            header[4],  # mtf_entry_count
            header[5],  # ptr_min_match_length
            header[6],  # mtf_min_match_length
            header[3],  # window_size_log2
            out,
        )
    return bytes(out)


def decompressed_size(src: bytes) -> int:
    """Return the total decompressed size from block headers, without decoding.

    Args:
        src: Raw XPRESS9 block data.

    Returns:
        Sum of all block ``orig_size`` fields.

    Raises:
        CorruptDataError: If the block headers are truncated or corrupt.
    """
    return sum(h[0] for h, _, _ in _session_blocks(src))


# --- Encoder constants (Xpress9EncLz77.c) ---

# ESE fixed "Cosmos Level 6" parameters (compression.cxx:1696-1706).
_ENC_WINDOW_SIZE_LOG2: Final = 16
_ENC_WINDOW_SIZE: Final = 1 << _ENC_WINDOW_SIZE_LOG2
_ENC_MTF_ENTRY_COUNT: Final = 4
_ENC_PTR_MIN_MATCH_LENGTH: Final = 4
_ENC_MTF_MIN_MATCH_LENGTH: Final = 2
_ENC_SESSION_SIGNATURE: Final = 0x12345678

# Hash table sizing (Xpress9EncLz77.c:1062-1102).
_HASH_TABLE_SIZE_LOG2: Final = 12
_HASH_TABLE_SIZE: Final = 1 << _HASH_TABLE_SIZE_LOG2
_HASH_MASK: Final = _HASH_TABLE_SIZE - 1

# Lookup depth: LookupDepth=1, +1 before the loop (Xpress9Lz77EncPass1.i:65).
_ENC_LOOKUP_DEPTH: Final = 1
_ENC_MAX_DEPTH: Final = _ENC_LOOKUP_DEPTH + 1

# IR buffer chunk size (Xpress9EncLz77.c:926,1570-1581).
_IR_BUFFER_SIZE: Final = 2 * _ENC_WINDOW_SIZE
_IR_CHUNK_SIZE: Final = _IR_BUFFER_SIZE // 3 - 256

# Maximum-offset-by-length table (Xpress9EncLz77.c:297-310).
_MAX_OFFSET_BY_LENGTH: Final[tuple[int, ...]] = (
    0,
    0,
    -(1 << 6),
    -(1 << 10),
    -(1 << 13),
    -(1 << 16),
)

# Token types for the intermediate representation.
_TOKEN_LIT: Final = 0
_TOKEN_PTR: Final = 1
_TOKEN_MTF: Final = 2


# --- Bit output (encoder) ---


class _BitWriter:
    """LSB-first bit writer, the encoding counterpart of ``_BitReader``.

    Port of the ``BIOWR`` macro family (Xpress9Internal.h:313-372).
    """

    __slots__ = ("_acc", "_buf", "_navail")

    def __init__(self) -> None:
        self._buf = bytearray()
        self._acc = 0
        self._navail = 0

    @property
    def bits_written(self) -> int:
        """Total bits written so far, including unflushed accumulator bits."""
        return len(self._buf) * 8 + self._navail

    def write(self, value: int, count: int) -> None:
        """Write ``count`` bits of ``value``, LSB first."""
        self._acc |= value << self._navail
        self._navail += count
        while self._navail >= 8:
            self._buf.append(self._acc & 0xFF)
            self._acc >>= 8
            self._navail -= 8

    def flush(self) -> None:
        """Write any remaining partial byte."""
        if self._navail > 0:
            self._buf.append(self._acc & 0xFF)
            self._acc = 0
            self._navail = 0

    def getvalue(self) -> bytes:
        """Return the written bytes. Must call ``flush`` first."""
        return bytes(self._buf)


# --- Canonical Huffman encoder ---


def _reverse_mask(value: int, bits: int) -> int:
    """Reverse the lowest ``bits`` bits (HuffmanReverseMask, Xpress9Misc.c:123-149)."""
    result = 0
    for _ in range(bits):
        result = (result << 1) | (value & 1)
        value >>= 1
    return result


def _compute_depths_from_tree(
    queue_leaf: list[tuple[int, int]],
    _queue_node: list[tuple[int, list[int]]],
    depths: list[int],
    _li: int,
    _ni: int,
    n: int,
) -> None:
    """Compute symbol depths by building and walking the Huffman tree."""
    if n <= 1:
        if n == 1:
            depths[queue_leaf[0][1]] = 1
        return

    sorted_symbols = [s for _, s in sorted(queue_leaf, key=lambda x: (x[0], x[1]))]
    sorted_counts = [c for c, _ in sorted(queue_leaf, key=lambda x: (x[0], x[1]))]

    class _Node:
        __slots__ = ("count", "depth", "left", "right", "symbol")

        def __init__(self, *, count: int, symbol: int = -1) -> None:
            self.count = count
            self.symbol = symbol
            self.depth = 0
            self.left: _Node | None = None
            self.right: _Node | None = None

    leaves = [_Node(count=sorted_counts[i], symbol=sorted_symbols[i]) for i in range(n)]
    internals: list[_Node] = []
    ssi = 0
    isi = 0

    def _pop_min_node() -> _Node:
        nonlocal ssi, isi
        sv = leaves[ssi].count if ssi < n else 2**63
        iv = internals[isi].count if isi < len(internals) else 2**63
        if sv <= iv:
            nd = leaves[ssi]
            ssi += 1
            return nd
        nd = internals[isi]
        isi += 1
        return nd

    for _ in range(n - 1):
        left = _pop_min_node()
        right = _pop_min_node()
        parent = _Node(count=left.count + right.count)
        parent.left = left
        parent.right = right
        internals.append(parent)

    root = internals[-1] if internals else leaves[0]

    stack: list[tuple[_Node, int]] = [(root, 0)]
    while stack:
        node, d = stack.pop()
        if node.symbol >= 0:
            depths[node.symbol] = max(d, 1)
        else:
            if node.left is not None:
                stack.append((node.left, d + 1))
            if node.right is not None:
                stack.append((node.right, d + 1))


def _build_huffman_codes(counts: list[int], alphabet_size: int, max_codeword_length: int) -> list[tuple[int, int]]:
    """Build canonical Huffman codewords from frequency counts.

    Port of ``Xpress9HuffmanCreateTree`` (Xpress9EncHuffman.c:673-797): build a tree,
    compute bit-lengths, truncate to ``max_codeword_length``, canonize, and create
    bit-reversed codewords. Returns ``(reversed_codeword, length)`` per symbol.
    """
    present = sorted(
        ((counts[i], i) for i in range(alphabet_size) if counts[i] > 0),
        key=lambda x: (x[0], x[1]),
    )
    n = len(present)
    result: list[tuple[int, int]] = [(0, 0)] * alphabet_size

    if n == 0:
        return result

    if n == 1:
        sym = present[0][1]
        result[sym] = (0, 1)
        return result

    queue_leaf = list(present)
    queue_node: list[tuple[int, list[int]]] = []
    li = 0
    ni = 0

    def _pop_min() -> tuple[int, list[int]]:
        nonlocal li, ni
        lv = queue_leaf[li][0] if li < len(queue_leaf) else 2**63
        nv = queue_node[ni][0] if ni < len(queue_node) else 2**63
        if lv <= nv:
            c, s = queue_leaf[li]
            li += 1
            return (c, [s])
        r = queue_node[ni]
        ni += 1
        return r

    for _ in range(n - 1):
        left_c, left_s = _pop_min()
        right_c, right_s = _pop_min()
        queue_node.append((left_c + right_c, left_s + right_s))

    depths = [0] * alphabet_size
    _compute_depths_from_tree(queue_leaf, queue_node, depths, li, ni, n)

    bit_length_count = [0] * 65
    for d in depths:
        if d > 0:
            bit_length_count[d] += 1

    # Truncate tree to max_codeword_length (HuffmanTruncateTree, Xpress9EncHuffman.c:460-508).
    for i in range(64, max_codeword_length, -1):
        while bit_length_count[i] > 0:
            j = max_codeword_length - 1
            while j > 0 and bit_length_count[j] == 0:
                j -= 1
            bit_length_count[j] -= 1
            bit_length_count[j + 1] += 2
            bit_length_count[i - 1] += 1
            bit_length_count[i] -= 2

    # Assign final lengths (HuffmanCanonizeTree, Xpress9EncHuffman.c:514-617).
    sorted_symbols = [s for _, s in present]
    sym_lengths = [0] * alphabet_size
    idx = 0
    for length in range(max_codeword_length, 0, -1):
        for _ in range(bit_length_count[length]):
            sym_lengths[sorted_symbols[idx]] = length
            idx += 1

    # Build canonical codewords (HuffmanCreateCodewords, Xpress9EncHuffman.c:624-665).
    by_length_symbol = sorted(
        ((sym_lengths[s], s) for s in range(alphabet_size) if sym_lengths[s] > 0),
        key=lambda x: (x[0], x[1]),
    )
    code = 0
    prev_len = 0
    for length, sym in by_length_symbol:
        code <<= length - prev_len
        result[sym] = (_reverse_mask(code, length), length)
        code += 1
        prev_len = length

    return result


# --- Huffman table serialization (encoder) ---


def _encode_small_table(writer: _BitWriter, code_lengths: list[tuple[int, int]]) -> None:
    """Write the 33-symbol small code-length table (Xpress9EncHuffman.c:941-964)."""
    prev = _SMALL_TABLE_INITIAL_PREV
    for sym in range(_TABLE_ALPHABET_SIZE):
        length = code_lengths[sym][1]
        if length == prev:
            writer.write(0, 1)
        else:
            writer.write(1, 1)
            if length > prev:
                writer.write(length - 1, 3)
            else:
                writer.write(length, 3)
            prev = length


def _write_length_sequence(
    writer: _BitWriter,
    lengths: list[int],
    symbols: list[int],
    meta_codes: list[tuple[int, int]],
    alphabet_size: int,
    fill_boundary: int,
) -> None:
    """Write the Mode 1 encoded length sequence into ``writer``."""
    prev_sym = _MAIN_TABLE_INITIAL_PREV
    sym_idx = 0
    i = 0
    while i < alphabet_size:
        k = lengths[i]
        if k != 0:
            meta_sym = symbols[sym_idx]
            sym_idx += 1
            cw, cl = meta_codes[meta_sym]
            writer.write(cw, cl)
            if k != prev_sym:
                prev_sym = k
            i += 1
        else:
            zero_start = i
            while i < alphabet_size and lengths[i] == 0:
                i += 1
            k_pos = zero_start
            while (k_pos ^ i) >= fill_boundary:
                cw, cl = meta_codes[_TABLE_FILL]
                writer.write(cw, cl)
                sym_idx += 1
                k_pos = (k_pos & ~(fill_boundary - 1)) + fill_boundary
            remaining = i - k_pos
            if remaining > 0:
                if remaining < _TABLE_ZERO_REPT_MIN_COUNT:
                    for _ in range(remaining):
                        cw, cl = meta_codes[0]
                        writer.write(cw, cl)
                        sym_idx += 1
                else:
                    cw, cl = meta_codes[_TABLE_ZERO_REPT]
                    writer.write(cw, cl)
                    sym_idx += 1
                    run = remaining - _TABLE_ZERO_REPT_MIN_COUNT
                    if run < 3:
                        writer.write(run, 2)
                    else:
                        writer.write(3, 2)
                        run -= 3
                        while run >= 7:
                            writer.write(7, 3)
                            run -= 7
                        writer.write(run, 3)


def _encode_huffman_table(
    writer: _BitWriter,
    codes: list[tuple[int, int]],
    counts: list[int],
    alphabet_size: int,
    fill_boundary: int,
) -> list[tuple[int, int]]:
    """Serialize one canonical-Huffman code-length table into the bitstream.

    Port of ``Xpress9HuffmanCreateAndEncodeTable`` (Xpress9EncHuffman.c:1078-1222):
    compare mode 0 (stored/uniform) vs mode 1 (Huffman-coded) and pick the cheaper one.
    """
    lengths = [c[1] for c in codes]

    # Mode 0 (stored/uniform) cost.
    msb = alphabet_size.bit_length() - 1
    threshold = (1 << (msb + 1)) - alphabet_size
    freq0 = sum(counts[i] for i in range(threshold))
    freq1 = sum(counts[i] for i in range(threshold, alphabet_size))
    mode0_cost = (freq0 + freq1) * msb + freq1 + 3

    # Mode 1 (Huffman-coded) data cost.
    huffman_data_cost = sum(counts[i] * lengths[i] for i in range(alphabet_size) if lengths[i] > 0)

    # Build Mode 1 opcode sequence.
    symbols: list[int] = []
    meta_counts = [0] * _TABLE_ALPHABET_SIZE
    prev_sym = _MAIN_TABLE_INITIAL_PREV
    i = 0
    while i < alphabet_size:
        k = lengths[i]
        if k != 0:
            sym: int
            if k == prev_sym:
                sym = _TABLE_PREV
            else:
                prev_sym = k
                if i >= fill_boundary:
                    row_val = lengths[i - fill_boundary]
                    if k == row_val:
                        sym = _TABLE_ROW_0
                    elif k == row_val + 1:
                        sym = _TABLE_ROW_1
                    else:
                        sym = k
                else:
                    sym = k
            meta_counts[sym] += 1
            symbols.append(sym)
            i += 1
        else:
            zero_start = i
            while i < alphabet_size and lengths[i] == 0:
                i += 1
            k_pos = zero_start
            while (k_pos ^ i) >= fill_boundary:
                symbols.append(_TABLE_FILL)
                meta_counts[_TABLE_FILL] += 1
                k_pos = (k_pos & ~(fill_boundary - 1)) + fill_boundary
            remaining = i - k_pos
            if remaining > 0:
                if remaining < _TABLE_ZERO_REPT_MIN_COUNT:
                    for _ in range(remaining):
                        symbols.append(0)
                        meta_counts[0] += 1
                else:
                    symbols.append(_TABLE_ZERO_REPT)
                    meta_counts[_TABLE_ZERO_REPT] += 1

    meta_codes = _build_huffman_codes(meta_counts, _TABLE_ALPHABET_SIZE, _SMALL_TABLE_MAX_LENGTH)

    # Measure Mode 1 cost exactly by writing to a scratch writer
    # (Xpress9EncHuffman.c:1129-1141).
    scratch = _BitWriter()
    scratch.write(_TABLE_ENCODING_HUFFMAN, 3)
    _encode_small_table(scratch, meta_codes)
    _write_length_sequence(scratch, lengths, symbols, meta_codes, alphabet_size, fill_boundary)
    mode1_cost = huffman_data_cost + scratch.bits_written

    if mode0_cost <= mode1_cost:
        writer.write(_TABLE_ENCODING_STORED, 3)
        uniform: list[tuple[int, int]] = [(0, 0)] * alphabet_size
        for j in range(threshold):
            uniform[j] = (_reverse_mask(j, msb), msb)
        base = threshold << 1
        for j in range(threshold, alphabet_size):
            uniform[j] = (_reverse_mask(base, msb + 1), msb + 1)
            base += 1
        return uniform

    writer.write(_TABLE_ENCODING_HUFFMAN, 3)
    _encode_small_table(writer, meta_codes)
    _write_length_sequence(writer, lengths, symbols, meta_codes, alphabet_size, fill_boundary)
    return codes


# --- LZ77 match finder and encoder ---


def _hash4(data: bytes, pos: int) -> int:
    """Hash 4 bytes at ``pos`` (Xpress9Lz77EncInsert.i:212-225, non-SSE2 scalar path)."""
    if pos + 4 > len(data):
        return 0
    v = data[pos] | (data[pos + 1] << 8) | (data[pos + 2] << 16) | (data[pos + 3] << 24)
    v = ((v ^ 0xDEADBEEF) + (v >> 5)) & 0xFFFFFFFF
    v = (v ^ (v >> 11)) & 0xFFFFFFFF
    return v & _HASH_MASK


def _hash_insert(data: bytes, pos: int, hash_table: list[int], p_next: list[int]) -> None:
    """Insert ``pos`` into the hash chain (Xpress9Lz77EncInsert.i:226-229)."""
    h = _hash4(data, pos)
    p_next[pos] = hash_table[h]
    hash_table[h] = pos


def _hash_insert_range(
    data: bytes, start: int, end: int, hash_table: list[int], p_next: list[int], data_size: int
) -> None:
    """Insert all positions in ``[start, end)`` into the hash chain."""
    hashable_limit = data_size - 4 if data_size >= 4 else 0
    for pos in range(start, end):
        if pos < hashable_limit:
            _hash_insert(data, pos, hash_table, p_next)
        else:
            p_next[pos] = 0


def _chain_lookup(
    data: bytes, pos: int, data_size: int, p_next: list[int], max_depth: int, best_len: int
) -> tuple[int, int]:
    """Walk the hash chain from ``pos`` looking for the longest match.

    Port of the Xpress9Lookup.i inner loop (DEEP_LOOKUP=1, TAIL_T=UInt16).
    Returns ``(best_offset_neg, best_length)``.
    """
    candidate = p_next[pos]
    saved_next_0 = p_next[0]
    p_next[0] = pos

    best_offset = 0
    depth_remaining = max_depth
    max_offset_table = _MAX_OFFSET_BY_LENGTH
    max_offset_len = len(max_offset_table) - 1

    while True:
        tail_pos = pos + best_len - 1
        if tail_pos + 1 >= data_size:
            break
        tail0 = data[tail_pos]
        tail1 = data[tail_pos + 1]

        found_candidate = -1
        checks_in_block = 0
        cur = candidate
        while checks_in_block < 8:
            next_cur = p_next[cur]
            if cur + best_len < data_size and data[cur + best_len - 1] == tail0 and data[cur + best_len] == tail1:
                found_candidate = cur
                candidate = next_cur
                break
            checks_in_block += 1

            cur2 = p_next[next_cur]
            if (
                next_cur + best_len < data_size
                and data[next_cur + best_len - 1] == tail0
                and data[next_cur + best_len] == tail1
            ):
                found_candidate = next_cur
                candidate = cur2
                break
            checks_in_block += 1
            cur = cur2

        if found_candidate < 0:
            depth_remaining -= 1
            if depth_remaining == 0:
                break
            candidate = cur
            continue

        if found_candidate >= pos:
            break

        i_offset = found_candidate - pos
        ml = 0
        while pos + ml < data_size and data[pos + ml] == data[found_candidate + ml]:
            ml += 1

        if ml > best_len and (ml > max_offset_len or i_offset > max_offset_table[ml]):
            best_len = ml
            best_offset = i_offset

        candidate = p_next[found_candidate]

    p_next[0] = saved_next_0
    return best_offset, best_len


def _check_mtf(data: bytes, pos: int, i_offset: int, data_size: int) -> int:
    """Check an MTF match at ``pos`` and return its length (Xpress9EncLz77.c:42-66)."""
    if pos + i_offset <= 0:
        return 0
    src = pos + i_offset
    if data[pos] != data[src] or data[pos + 1] != data[src + 1]:
        return 0
    ml = _ENC_MTF_MIN_MATCH_LENGTH
    while pos + ml < data_size and data[pos + ml] == data[src + ml]:
        ml += 1
    return ml


def _emit_mtf(
    tokens: list[tuple[int, ...]],
    encode_idx: int,
    offset_neg: int,
    length: int,
    mtf_slot: int,
    mtf_0: int,
    mtf_1: int,
    mtf_2: int,
    mtf_3: int,
) -> tuple[int, int, int, int]:
    """Emit an MTF token and perform UPDATE_MTF, returning the updated MTF state."""
    tokens.append((_TOKEN_MTF, encode_idx, -offset_neg, length))
    if mtf_slot >= 3:
        mtf_3 = mtf_2
    if mtf_slot >= 2:
        mtf_2 = mtf_1
    mtf_1 = mtf_0
    mtf_0 = offset_neg
    return mtf_0, mtf_1, mtf_2, mtf_3


def _check_all_mtf(
    data: bytes,
    pos: int,
    data_size: int,
    mtf_last_ptr: int,
    mtf_0: int,
    mtf_1: int,
    mtf_2: int,
    mtf_3: int,
) -> tuple[int, int, int]:
    """Check all 4 MTF slots at ``pos`` (Xpress9Lz77EncPass1.i:80-93)."""
    if mtf_last_ptr == 0:
        ml = _check_mtf(data, pos, mtf_0, data_size)
        if ml >= _ENC_MTF_MIN_MATCH_LENGTH:
            return ml, 0, 0
    ml = _check_mtf(data, pos, mtf_1, data_size)
    if ml >= _ENC_MTF_MIN_MATCH_LENGTH:
        return ml, 1 + mtf_last_ptr, 1
    ml = _check_mtf(data, pos, mtf_2, data_size)
    if ml >= _ENC_MTF_MIN_MATCH_LENGTH:
        return ml, 2 + mtf_last_ptr, 2
    ml = _check_mtf(data, pos, mtf_3, data_size)
    if ml >= _ENC_MTF_MIN_MATCH_LENGTH:
        return ml, 3 + mtf_last_ptr, 3
    return 0, 0, 0


def _lookahead_check_mtf(
    data: bytes,
    pos: int,
    data_size: int,
    threshold: int,
    mtf_0: int,
    mtf_1: int,
    mtf_2: int,
    mtf_3: int,
) -> tuple[int, int, int]:
    """Check all 4 MTF slots for lookahead paths (Xpress9EncLz77.c:71-136)."""
    for slot, off in enumerate((mtf_0, mtf_1, mtf_2, mtf_3)):
        ml = _check_mtf(data, pos, off, data_size)
        if ml >= threshold:
            return ml, slot, slot
    return 0, 0, 0


def _lz77_tokenize(data: bytes) -> list[tuple[int, ...]]:
    """LZ77 tokenizer with lazy match evaluation matching the C reference encoder.

    Port of Xpress9Lz77EncPass1.i (DEEP_LOOKUP=1, LZ77_MTF=4, LAZY_MATCH_EVALUATION).
    """
    data_size = len(data)
    tokens: list[tuple[int, ...]] = []
    if data_size == 0:
        return tokens

    hash_table = [0] * _HASH_TABLE_SIZE
    p_next = [0] * data_size

    hash_insert_pos = 0
    mtf_0 = -1
    mtf_1 = -1
    mtf_2 = -1
    mtf_3 = -1
    mtf_last_ptr = 0

    max_depth = _ENC_MAX_DEPTH
    pos = 0
    bytes_copied = 0

    while bytes_copied < data_size:
        remaining = data_size - bytes_copied
        chunk = min(_IR_CHUNK_SIZE, remaining)
        bytes_copied += chunk
        chunk_data_size = bytes_copied

        _hash_insert_range(data, hash_insert_pos, bytes_copied, hash_table, p_next, data_size)
        hash_insert_pos = min(bytes_copied, max(data_size - 4, 0)) if data_size >= 4 else 0
        stop_position = hash_insert_pos

        while pos < stop_position:
            # MTF checks.
            mtf_ml, mtf_ei, mtf_sl = _check_all_mtf(
                data, pos, chunk_data_size, mtf_last_ptr, mtf_0, mtf_1, mtf_2, mtf_3
            )
            if mtf_ml > 0:
                offset_neg = (mtf_0, mtf_1, mtf_2, mtf_3)[mtf_sl]
                mtf_0, mtf_1, mtf_2, mtf_3 = _emit_mtf(
                    tokens, mtf_ei, offset_neg, mtf_ml, mtf_sl, mtf_0, mtf_1, mtf_2, mtf_3
                )
                mtf_last_ptr = -1
                pos += mtf_ml
                continue

            # Hash chain lookup.
            if p_next[pos] != 0:
                best_len = _ENC_PTR_MIN_MATCH_LENGTH - 1
                best_offset, best_len = _chain_lookup(data, pos, chunk_data_size, p_next, max_depth, best_len)

                if best_len >= _ENC_PTR_MIN_MATCH_LENGTH:
                    # LAZY_MATCH_EVALUATION.
                    if pos + 2 < stop_position and p_next[pos + 1] != 0:
                        saved_best_len = best_len
                        saved_best_offset = best_offset

                        la_threshold = max(saved_best_len - 3, _ENC_MTF_MIN_MATCH_LENGTH)
                        la_ml, la_ei, la_sl = _lookahead_check_mtf(
                            data,
                            pos + 1,
                            chunk_data_size,
                            la_threshold,
                            mtf_0,
                            mtf_1,
                            mtf_2,
                            mtf_3,
                        )
                        if la_ml >= la_threshold:
                            tokens.append((_TOKEN_LIT, data[pos]))
                            offset_neg = (mtf_0, mtf_1, mtf_2, mtf_3)[la_sl]
                            mtf_0, mtf_1, mtf_2, mtf_3 = _emit_mtf(
                                tokens,
                                la_ei,
                                offset_neg,
                                la_ml,
                                la_sl,
                                mtf_0,
                                mtf_1,
                                mtf_2,
                                mtf_3,
                            )
                            mtf_last_ptr = -1
                            pos += 1 + la_ml
                            continue

                        la1_best_len = best_len
                        la1_best_offset, la1_best_len = _chain_lookup(
                            data,
                            pos + 1,
                            chunk_data_size,
                            p_next,
                            max(max_depth // 2, 1),
                            la1_best_len,
                        )

                        if la1_best_len > saved_best_len:
                            if p_next[pos + 2] != 0:
                                saved_best_len2 = la1_best_len
                                saved_best_offset2 = la1_best_offset

                                la2_threshold = max(saved_best_len2 - 3, _ENC_MTF_MIN_MATCH_LENGTH)
                                la2_ml, la2_ei, la2_sl = _lookahead_check_mtf(
                                    data,
                                    pos + 2,
                                    chunk_data_size,
                                    la2_threshold,
                                    mtf_0,
                                    mtf_1,
                                    mtf_2,
                                    mtf_3,
                                )
                                if la2_ml >= la2_threshold:
                                    tokens.append((_TOKEN_LIT, data[pos]))
                                    tokens.append((_TOKEN_LIT, data[pos + 1]))
                                    offset_neg = (mtf_0, mtf_1, mtf_2, mtf_3)[la2_sl]
                                    mtf_0, mtf_1, mtf_2, mtf_3 = _emit_mtf(
                                        tokens,
                                        la2_ei,
                                        offset_neg,
                                        la2_ml,
                                        la2_sl,
                                        mtf_0,
                                        mtf_1,
                                        mtf_2,
                                        mtf_3,
                                    )
                                    mtf_last_ptr = -1
                                    pos += 2 + la2_ml
                                    continue

                                la2_best_len = la1_best_len
                                la2_best_offset, la2_best_len = _chain_lookup(
                                    data,
                                    pos + 2,
                                    chunk_data_size,
                                    p_next,
                                    max(max_depth // 4, 1),
                                    la2_best_len,
                                )

                                if la2_best_len > saved_best_len2:
                                    tokens.append((_TOKEN_LIT, data[pos]))
                                    tokens.append((_TOKEN_LIT, data[pos + 1]))
                                    pos += 2
                                    best_offset = la2_best_offset
                                    best_len = la2_best_len
                                else:
                                    tokens.append((_TOKEN_LIT, data[pos]))
                                    pos += 1
                                    best_offset = saved_best_offset2
                                    best_len = saved_best_len2
                            else:
                                tokens.append((_TOKEN_LIT, data[pos]))
                                pos += 1
                                best_offset = la1_best_offset
                                best_len = la1_best_len
                        else:
                            la2_threshold = max(saved_best_len - 3, _ENC_MTF_MIN_MATCH_LENGTH)
                            la2_ml, la2_ei, la2_sl = _lookahead_check_mtf(
                                data,
                                pos + 2,
                                chunk_data_size,
                                la2_threshold,
                                mtf_0,
                                mtf_1,
                                mtf_2,
                                mtf_3,
                            )
                            if la2_ml >= la2_threshold:
                                tokens.append((_TOKEN_LIT, data[pos]))
                                tokens.append((_TOKEN_LIT, data[pos + 1]))
                                offset_neg = (mtf_0, mtf_1, mtf_2, mtf_3)[la2_sl]
                                mtf_0, mtf_1, mtf_2, mtf_3 = _emit_mtf(
                                    tokens,
                                    la2_ei,
                                    offset_neg,
                                    la2_ml,
                                    la2_sl,
                                    mtf_0,
                                    mtf_1,
                                    mtf_2,
                                    mtf_3,
                                )
                                mtf_last_ptr = -1
                                pos += 2 + la2_ml
                                continue

                            best_offset = saved_best_offset
                            best_len = saved_best_len

                    # Emit pointer match.
                    tokens.append((_TOKEN_PTR, -best_offset, best_len))
                    mtf_3 = mtf_2
                    mtf_2 = mtf_1
                    mtf_1 = mtf_0
                    mtf_0 = best_offset
                    mtf_last_ptr = -1
                    pos += best_len
                    continue

            # Literal loop (Xpress9Lz77EncPass1.i:243-267).
            mtf_last_ptr = 0
            while True:
                tokens.append((_TOKEN_LIT, data[pos]))
                pos += 1
                if pos >= stop_position:
                    break
                cand = p_next[pos]
                if cand == 0:
                    continue
                if (
                    pos + 3 < chunk_data_size
                    and cand + 3 < chunk_data_size
                    and data[pos] == data[cand]
                    and data[pos + 1] == data[cand + 1]
                    and data[pos + 2] == data[cand + 2]
                    and data[pos + 3] == data[cand + 3]
                ):
                    break

    # Flush trailing unhashed positions as literals.
    while pos < data_size:
        tokens.append((_TOKEN_LIT, data[pos]))
        mtf_last_ptr = 0
        pos += 1

    return tokens


# --- Token encoding ---


def _collect_frequencies(tokens: list[tuple[int, ...]]) -> tuple[list[int], list[int], int]:
    """Collect Huffman frequency tables from the token stream."""
    short_counts = [0] * _SHORT_SYMBOL_ALPHABET_SIZE
    long_counts = [0] * _LONG_LENGTH_ALPHABET_SIZE
    extra_bits = 0

    for token in tokens:
        if token[0] == _TOKEN_LIT:
            short_counts[token[1]] += 1
        elif token[0] == _TOKEN_PTR:
            offset, length = token[1], token[2]
            msb_offset = offset.bit_length() - 1
            extra_bits += msb_offset
            sym_base = (msb_offset + 16 + _ENC_MTF_ENTRY_COUNT) << _MAX_SHORT_LENGTH_LOG
            adj_length = length - _ENC_PTR_MIN_MATCH_LENGTH
            if adj_length < _MAX_SHORT_LENGTH - 1:
                short_counts[sym_base + adj_length] += 1
            else:
                short_counts[sym_base + _MAX_SHORT_LENGTH - 1] += 1
                long_length = adj_length - (_MAX_SHORT_LENGTH - 1)
                if long_length <= _MAX_LONG_LENGTH - 1:
                    long_counts[long_length] += 1
                else:
                    escaped = long_length - (_MAX_LONG_LENGTH - 1)
                    msb_len = escaped.bit_length() - 1
                    extra_bits += msb_len
                    long_counts[msb_len + _MAX_LONG_LENGTH] += 1
        else:  # _TOKEN_MTF
            mtf_index, _offset, length = token[1], token[2], token[3]
            sym_base = (mtf_index + 16) << _MAX_SHORT_LENGTH_LOG
            adj_length = length - _ENC_MTF_MIN_MATCH_LENGTH
            if adj_length < _MAX_SHORT_LENGTH - 1:
                short_counts[sym_base + adj_length] += 1
            else:
                short_counts[sym_base + _MAX_SHORT_LENGTH - 1] += 1
                long_length = adj_length - (_MAX_SHORT_LENGTH - 1)
                if long_length <= _MAX_LONG_LENGTH - 1:
                    long_counts[long_length] += 1
                else:
                    escaped = long_length - (_MAX_LONG_LENGTH - 1)
                    msb_len = escaped.bit_length() - 1
                    extra_bits += msb_len
                    long_counts[msb_len + _MAX_LONG_LENGTH] += 1

    return short_counts, long_counts, extra_bits


def _encode_tokens(
    writer: _BitWriter,
    tokens: list[tuple[int, ...]],
    short_codes: list[tuple[int, int]],
    long_codes: list[tuple[int, int]],
) -> None:
    """Encode the LZ77 token stream using Huffman codes (Xpress9Lz77EncPass2.i:1-107)."""
    for token in tokens:
        if token[0] == _TOKEN_LIT:
            cw, cl = short_codes[token[1]]
            writer.write(cw, cl)
        elif token[0] == _TOKEN_PTR:
            offset, length = token[1], token[2]
            msb_offset = offset.bit_length() - 1
            low_offset = offset - (1 << msb_offset)
            sym_base = (msb_offset + 16 + _ENC_MTF_ENTRY_COUNT) << _MAX_SHORT_LENGTH_LOG
            adj_length = length - _ENC_PTR_MIN_MATCH_LENGTH

            if adj_length < _MAX_SHORT_LENGTH - 1:
                cw, cl = short_codes[sym_base + adj_length]
                writer.write(cw, cl)
            else:
                cw, cl = short_codes[sym_base + _MAX_SHORT_LENGTH - 1]
                writer.write(cw, cl)
                long_length = adj_length - (_MAX_SHORT_LENGTH - 1)
                if long_length <= _MAX_LONG_LENGTH - 1:
                    cw, cl = long_codes[long_length]
                    writer.write(cw, cl)
                else:
                    escaped = long_length - (_MAX_LONG_LENGTH - 1)
                    msb_len = escaped.bit_length() - 1
                    low_len = escaped - (1 << msb_len)
                    cw, cl = long_codes[msb_len + _MAX_LONG_LENGTH]
                    writer.write(cw, cl)
                    writer.write(low_len, msb_len)

            writer.write(low_offset, msb_offset)

        else:  # _TOKEN_MTF
            mtf_index, _offset, length = token[1], token[2], token[3]
            sym_base = (mtf_index + 16) << _MAX_SHORT_LENGTH_LOG
            adj_length = length - _ENC_MTF_MIN_MATCH_LENGTH

            if adj_length < _MAX_SHORT_LENGTH - 1:
                cw, cl = short_codes[sym_base + adj_length]
                writer.write(cw, cl)
            else:
                cw, cl = short_codes[sym_base + _MAX_SHORT_LENGTH - 1]
                writer.write(cw, cl)
                long_length = adj_length - (_MAX_SHORT_LENGTH - 1)
                if long_length <= _MAX_LONG_LENGTH - 1:
                    cw, cl = long_codes[long_length]
                    writer.write(cw, cl)
                else:
                    escaped = long_length - (_MAX_LONG_LENGTH - 1)
                    msb_len = escaped.bit_length() - 1
                    low_len = escaped - (1 << msb_len)
                    cw, cl = long_codes[msb_len + _MAX_LONG_LENGTH]
                    writer.write(cw, cl)
                    writer.write(low_len, msb_len)


def _encode_block(data: bytes, block_index: int) -> bytes:
    """Encode one XPRESS9 block: 32-byte header followed by bitstream.

    Implements block assembly (Xpress9EncLz77.c:1367-1512): MTF initial state, two
    Huffman tables, the LZ77 token stream, and the 8-word block header with CRC-32C.
    """
    tokens = _lz77_tokenize(data)
    short_counts, long_counts, _extra_bits = _collect_frequencies(tokens)

    if sum(short_counts) == 0:
        short_counts[0] = 1
    if sum(long_counts) == 0:
        long_counts[0] = 1
        long_counts[1] = 1
    elif sum(1 for c in long_counts if c > 0) == 1:
        for j in range(_LONG_LENGTH_ALPHABET_SIZE):
            if long_counts[j] == 0:
                long_counts[j] = 1
                break

    short_codes = _build_huffman_codes(short_counts, _SHORT_SYMBOL_ALPHABET_SIZE, _MAX_CODEWORD_LENGTH)
    long_codes = _build_huffman_codes(long_counts, _LONG_LENGTH_ALPHABET_SIZE, _MAX_CODEWORD_LENGTH)

    writer = _BitWriter()

    # MTF initial state (Xpress9EncLz77.c:1393-1410).
    writer.write(0, 1)  # iMtfLastPtr
    for _ in range(_ENC_MTF_ENTRY_COUNT):
        writer.write(0, 5)  # offset 1 encoded as Elias-gamma: msb=0

    # Write Huffman tables.
    short_codes = _encode_huffman_table(
        writer, short_codes, short_counts, _SHORT_SYMBOL_ALPHABET_SIZE, _MAX_SHORT_LENGTH
    )
    long_codes = _encode_huffman_table(writer, long_codes, long_counts, _LONG_LENGTH_ALPHABET_SIZE, _MAX_SHORT_LENGTH)

    huffman_table_bits = writer.bits_written
    _encode_tokens(writer, tokens, short_codes, long_codes)

    exact_bits = writer.bits_written
    writer.flush()
    bitstream = writer.getvalue()

    comp_size_bits = BLOCK_HEADER_SIZE * 8 + exact_bits

    # Build flags (Xpress9EncLz77.c:1464-1483).
    flags = huffman_table_bits & 0x1FFF
    flags |= ((_ENC_WINDOW_SIZE_LOG2 - 16) & 7) << 13
    flags |= (_ENC_MTF_ENTRY_COUNT >> 1) << 16
    flags |= ((_ENC_PTR_MIN_MATCH_LENGTH - 3) & 1) << 18
    flags |= ((_ENC_MTF_MIN_MATCH_LENGTH - 2) & 1) << 19

    header_words = struct.pack(
        "<7I",
        _XPRESS9_MAGIC,
        len(data),
        comp_size_bits,
        flags,
        0,  # reserved
        _ENC_SESSION_SIGNATURE,
        block_index,
    )
    header_crc = _crc32c(header_words)
    header = header_words + struct.pack("<I", header_crc)

    return header + bitstream


def compress(src: bytes) -> bytes:
    """Compress data into raw XPRESS9 blocks.

    Encodes the input as a single XPRESS9 block using the fixed "Cosmos Level 6"
    parameters (MTF=4, PtrMin=4, MtfMin=2, window 2**16). The result is the raw
    block data (32-byte header + bitstream) with no ESE framing.

    Args:
        src: The plaintext data to compress.

    Returns:
        Raw XPRESS9 block data.

    Raises:
        CorruptDataError: If the input is empty.
    """
    if not src:
        raise CorruptDataError("cannot compress empty input")
    return _encode_block(src, 0)
