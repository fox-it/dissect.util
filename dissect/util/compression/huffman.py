from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dissect.util.stream import BitStream


class HuffmanDecoder:
    """Canonical Huffman decoder using a lookup table.

    Formats that describe their Huffman tree in some other way are expected to convert it to a list of code lengths
    and import those using :meth:`import_lengths`.

    Decoding works on any bit stream that provides ``peek`` and ``remove`` methods, such as
    :class:`~dissect.util.stream.BitStream`.

    Args:
        num_codes: The number of codes in the alphabet.
        max_bits: The maximum length of a code in bits.
    """

    def __init__(self, num_codes: int, max_bits: int):
        self.num_codes = num_codes
        self.max_bits = max_bits

        self.lengths = [0] * num_codes
        self.codes = [0] * num_codes
        self.table: list[tuple[int, int] | None] = [None] * (1 << max_bits)

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
        self._assign_canonical_codes(longest_first)
        self._build_lookup_table()

    def decode(self, stream: BitStream) -> int:
        """Decode a single symbol.

        Args:
            stream: The bit stream to decode from.
        """
        if (entry := self.table[stream.peek(self.max_bits)]) is None:
            raise ValueError("Invalid Huffman code")

        symbol, length = entry
        stream.remove(length)
        return symbol

    def _assign_canonical_codes(self, longest_first: bool) -> None:
        histogram = [0] * (self.max_bits + 1)
        for length in self.lengths:
            if length > self.max_bits:
                raise ValueError("Invalid Huffman code length")
            histogram[length] += 1

        # Make sure the codes exactly fill the code space, a tree with fewer than two codes can't be complete
        used = sum(histogram[length] << (self.max_bits - length) for length in range(1, self.max_bits + 1))
        if used > 1 << self.max_bits or (used < 1 << self.max_bits and sum(histogram[1:]) > 1):
            raise ValueError("Invalid Huffman tree")

        # For each code length, determine the starting code
        start = 0
        if longest_first:
            for length in range(self.max_bits, 0, -1):
                histogram[length], start = start, (start + histogram[length]) >> 1
        else:
            for length in range(1, self.max_bits + 1):
                histogram[length], start = start, (start + histogram[length]) << 1

        self.codes = [0] * self.num_codes
        for symbol, length in enumerate(self.lengths):
            if length > 0:
                self.codes[symbol] = histogram[length]
                histogram[length] += 1

    def _build_lookup_table(self) -> None:
        self.table = [None] * (1 << self.max_bits)
        for symbol, (length, code) in enumerate(zip(self.lengths, self.codes, strict=True)):
            if length > 0:
                shift = self.max_bits - length
                self.table[code << shift : (code + 1) << shift] = [(symbol, length)] * (1 << shift)
