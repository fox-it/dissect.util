"""Canonical Huffman coding.

Decoder and encoder for the canonical Huffman codes of the formats in this package, such as LZXPRESS Huffman and
XPRESS9. Formats only store the code lengths, the codes follow from those.
"""

from __future__ import annotations

import heapq
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dissect.util.stream import BitStream

# Codes up to this length are in the lookup table, longer codes are in a dict, so that the table stays small
MAX_TABLE_BITS = 15


class HuffmanDecoder:
    """Canonical Huffman decoder using a lookup table.

    Codes that are longer than ``MAX_TABLE_BITS`` are looked up in a dict instead, which is slower but keeps the
    memory use limited for formats that allow very long codes, such as XPRESS9.

    Formats that describe their Huffman tree in some other way are expected to convert it to a list of code lengths
    and import those using :meth:`import_lengths`.

    Decoding works on any bit stream that provides ``peek`` and ``remove`` methods, such as
    :class:`~dissect.util.stream.BitStream`.

    Args:
        num_codes: The number of codes in the alphabet.
        max_bits: The maximum length of a code in bits.
        lsb_first: Whether the bit stream reads the first bit of a code into the least significant bit, like DEFLATE.
    """

    def __init__(self, num_codes: int, max_bits: int, lsb_first: bool = False):
        self.num_codes = num_codes
        self.max_bits = max_bits
        self.lsb_first = lsb_first

        self.table_bits = min(max_bits, MAX_TABLE_BITS)

        self.lengths = [0] * num_codes
        self.codes = [0] * num_codes
        self.table: list[tuple[int, int] | None] = [None] * (1 << self.table_bits)
        self.long_codes: dict[tuple[int, int], int] = {}

    def import_lengths(self, lengths: list[int], longest_first: bool = False) -> None:
        """Import the code lengths of all symbols and build the lookup table.

        Codes are assigned canonically, ordered by code length and symbol. By default the lowest codes are assigned
        to the shortest code lengths, like DEFLATE. Some formats (e.g. MAME) assign the lowest codes to the longest
        code lengths instead.

        The code lengths must describe a complete tree, unless fewer than two symbols are used.

        Args:
            lengths: The code length of each symbol, where 0 means that the symbol is unused.
            longest_first: Whether to assign the lowest codes to the longest code lengths.
        """
        if len(lengths) != self.num_codes:
            raise ValueError("Invalid number of Huffman code lengths")

        self.lengths = lengths
        self.codes = _assign_codes(lengths, self.max_bits, longest_first)
        self._build_lookup_table()

    def decode(self, stream: BitStream) -> int:
        """Decode a single symbol.

        Args:
            stream: The bit stream to decode from.
        """
        if (entry := self.table[stream.peek(self.table_bits)]) is None:
            # Codes that are longer than the lookup table are looked up by their length and value
            bits = stream.peek(self.max_bits)
            for length in range(self.table_bits + 1, self.max_bits + 1):
                code = bits & ((1 << length) - 1) if self.lsb_first else bits >> (self.max_bits - length)
                if (symbol := self.long_codes.get((length, code))) is not None:
                    break
            else:
                raise ValueError("Invalid Huffman code")
        else:
            symbol, length = entry

        stream.remove(length)
        return symbol

    def _build_lookup_table(self) -> None:
        self.table = [None] * (1 << self.table_bits)
        self.long_codes = {}
        for symbol, (length, code) in enumerate(zip(self.lengths, self.codes, strict=True)):
            if length > self.table_bits:
                self.long_codes[(length, _reverse_bits(code, length) if self.lsb_first else code)] = symbol
            elif length > 0:
                shift = self.table_bits - length
                if self.lsb_first:
                    # The code is in the low bits in reverse, the bits above it belong to the codes that follow
                    self.table[_reverse_bits(code, length) :: 1 << length] = [(symbol, length)] * (1 << shift)
                else:
                    self.table[code << shift : (code + 1) << shift] = [(symbol, length)] * (1 << shift)


class HuffmanEncoder:
    """Canonical Huffman encoder.

    Builds the code lengths from the number of occurrences of each symbol using :meth:`import_counts`. The codes are
    assigned in the same way as :class:`HuffmanDecoder` does by default, so formats only have to store the code lengths.

    Args:
        num_codes: The number of codes in the alphabet.
        max_bits: The maximum length of a code in bits.
        lsb_first: Whether the bit stream writes the first bit of a code from the least significant bit, like DEFLATE.
    """

    def __init__(self, num_codes: int, max_bits: int, lsb_first: bool = False):
        self.num_codes = num_codes
        self.max_bits = max_bits
        self.lsb_first = lsb_first

        self.lengths = [0] * num_codes
        self.codes = [0] * num_codes

    def import_counts(self, counts: list[int]) -> None:
        """Import the number of occurrences of all symbols and build the code lengths and codes.

        If only one symbol is used, it gets a code length of 1. This doesn't describe a complete tree, so formats that
        require one must use at least two symbols.

        If ``lsb_first`` is set, the bits of the codes are reversed, so that the first bit of a code is written first.

        Args:
            counts: The number of occurrences of each symbol, where 0 means that the symbol is unused.
        """
        if len(counts) != self.num_codes:
            raise ValueError("Invalid number of Huffman symbol counts")

        if len(counts) - counts.count(0) > 1 << self.max_bits:
            raise ValueError("Too many Huffman symbols for the maximum code length")

        while True:
            lengths = [0] * self.num_codes

            heap = [(count, [symbol]) for symbol, count in enumerate(counts) if count]
            heapq.heapify(heap)
            if len(heap) == 1:
                lengths[heap[0][1][0]] = 1

            # Merge the two least occurring subtrees until one tree remains, each merge adds a bit to their codes
            while len(heap) > 1:
                count_a, symbols_a = heapq.heappop(heap)
                count_b, symbols_b = heapq.heappop(heap)
                symbols = symbols_a + symbols_b
                for symbol in symbols:
                    lengths[symbol] += 1
                heapq.heappush(heap, (count_a + count_b, symbols))

            if max(lengths) <= self.max_bits:
                break

            # Halve the counts to make the tree less deep, used symbols keep a count of at least 1
            counts = [(count + 1) >> 1 for count in counts]

        self.lengths = lengths
        self.codes = _assign_codes(lengths, self.max_bits)
        if self.lsb_first:
            self.codes = [_reverse_bits(code, length) for code, length in zip(self.codes, lengths, strict=True)]


def _assign_codes(lengths: list[int], max_bits: int, longest_first: bool = False) -> list[int]:
    histogram = [0] * (max_bits + 1)
    for length in lengths:
        if length > max_bits:
            raise ValueError("Invalid Huffman code length")
        histogram[length] += 1

    # Make sure the codes exactly fill the code space, a tree with fewer than two codes can't be complete
    used = sum(histogram[length] << (max_bits - length) for length in range(1, max_bits + 1))
    if used > 1 << max_bits or (used < 1 << max_bits and sum(histogram[1:]) > 1):
        raise ValueError("Invalid Huffman tree")

    # For each code length, determine the starting code
    start = 0
    if longest_first:
        for length in range(max_bits, 0, -1):
            histogram[length], start = start, (start + histogram[length]) >> 1
    else:
        for length in range(1, max_bits + 1):
            histogram[length], start = start, (start + histogram[length]) << 1

    codes = [0] * len(lengths)
    for symbol, length in enumerate(lengths):
        if length > 0:
            codes[symbol] = histogram[length]
            histogram[length] += 1

    return codes


def _reverse_bits(value: int, num_bits: int) -> int:
    return int(f"{value:0{num_bits}b}"[::-1], 2)
