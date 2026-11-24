from __future__ import annotations

import io

import pytest

from dissect.util.compression.huffman import HuffmanDecoder, HuffmanEncoder
from dissect.util.compression.lzxpress9 import _BitStream
from dissect.util.stream import BitStream


def test_huffman_import_lengths() -> None:
    # Example from RFC 1951, section 3.2.2
    decoder = HuffmanDecoder(8, 4)
    decoder.import_lengths([3, 3, 3, 3, 3, 2, 4, 4])

    assert decoder.codes == [0b010, 0b011, 0b100, 0b101, 0b110, 0b00, 0b1110, 0b1111]

    stream = BitStream(io.BytesIO(bytes([0b00010011, 0b11101111])))
    assert [decoder.decode(stream) for _ in range(5)] == [5, 0, 1, 6, 7]


def test_huffman_import_lengths_longest_first() -> None:
    decoder = HuffmanDecoder(8, 4)
    decoder.import_lengths([3, 3, 3, 3, 3, 2, 4, 4], longest_first=True)

    assert decoder.codes == [0b001, 0b010, 0b011, 0b100, 0b101, 0b11, 0b0000, 0b0001]

    stream = BitStream(io.BytesIO(bytes([0b11001010, 0b00000001])))
    assert [decoder.decode(stream) for _ in range(5)] == [5, 0, 1, 6, 7]


def test_huffman_import_lengths_invalid() -> None:
    decoder = HuffmanDecoder(4, 2)

    with pytest.raises(ValueError, match="Invalid number of Huffman code lengths"):
        decoder.import_lengths([1, 1])

    with pytest.raises(ValueError, match="Invalid Huffman code length"):
        decoder.import_lengths([1, 3, 0, 0])

    with pytest.raises(ValueError, match="Invalid Huffman tree"):
        decoder.import_lengths([1, 1, 1, 0])

    with pytest.raises(ValueError, match="Invalid Huffman tree"):
        decoder.import_lengths([1, 1, 1, 0], longest_first=True)

    # Incomplete trees
    with pytest.raises(ValueError, match="Invalid Huffman tree"):
        decoder.import_lengths([1, 2, 0, 0])

    with pytest.raises(ValueError, match="Invalid Huffman tree"):
        decoder.import_lengths([1, 2, 0, 0], longest_first=True)


def test_huffman_import_lengths_single_code() -> None:
    decoder = HuffmanDecoder(4, 2)

    # Trees with fewer than two codes can't be complete, but are allowed
    decoder.import_lengths([0, 0, 0, 0])
    decoder.import_lengths([0, 0, 2, 0])
    assert decoder.codes == [0, 0, 0, 0]

    decoder.import_lengths([0, 0, 2, 0], longest_first=True)
    assert decoder.codes == [0, 0, 0, 0]


def test_huffman_decode_invalid() -> None:
    decoder = HuffmanDecoder(4, 2)
    decoder.import_lengths([1, 0, 0, 0])

    stream = BitStream(io.BytesIO(b"\xff"))
    with pytest.raises(ValueError, match="Invalid Huffman code"):
        decoder.decode(stream)

    # A single code that is too long for the lookup table
    decoder = HuffmanDecoder(2, 17)
    decoder.import_lengths([0, 17])

    stream = BitStream(io.BytesIO(b"\xff\xff\xff"))
    with pytest.raises(ValueError, match=r"^Invalid Huffman code$"):
        decoder.decode(stream)


@pytest.mark.parametrize("lsb_first", [False, True])
def test_huffman_decode_long_codes(lsb_first: bool) -> None:
    """Test whether codes that are too long for the lookup table are decoded, without making the table larger."""
    # XPRESS9 allows codes of 27 bits
    decoder = HuffmanDecoder(28, 27, lsb_first=lsb_first)
    decoder.import_lengths([*range(1, 27), 27, 27])
    assert len(decoder.table) == 1 << 15

    # The codes of symbols 27, 15, 0 and 26, symbol 27 is all one bits and the others end with a zero bit
    bits = "1" * 27 + "1" * 15 + "0" + "0" + "1" * 26 + "0"
    bits += "0" * (-len(bits) % 8)
    if lsb_first:
        stream = _BitStream(int(bits[::-1], 2).to_bytes(len(bits) // 8, "little"))
    else:
        stream = BitStream(io.BytesIO(int(bits, 2).to_bytes(len(bits) // 8, "big")))

    assert [decoder.decode(stream) for _ in range(4)] == [27, 15, 0, 26]


def test_huffman_import_lengths_lsb_first() -> None:
    """Test whether codes are decoded from a bit stream that reads the least significant bit first."""
    decoder = HuffmanDecoder(8, 4, lsb_first=True)
    decoder.import_lengths([3, 3, 3, 3, 3, 2, 4, 4])

    assert decoder.codes == [0b010, 0b011, 0b100, 0b101, 0b110, 0b00, 0b1110, 0b1111]

    # The same codes as in test_huffman_import_lengths, starting at the least significant bit of each byte
    stream = _BitStream(bytes([0b11001000, 0b11110111]))
    assert [decoder.decode(stream) for _ in range(5)] == [5, 0, 1, 6, 7]


def test_huffman_encoder_import_counts() -> None:
    """Test whether the code lengths and codes are built from the symbol counts."""
    # Counts for the example from RFC 1951, section 3.2.2
    encoder = HuffmanEncoder(8, 4)
    encoder.import_counts([4, 4, 4, 4, 4, 8, 2, 2])

    assert encoder.lengths == [3, 3, 3, 3, 3, 2, 4, 4]
    assert encoder.codes == [0b010, 0b011, 0b100, 0b101, 0b110, 0b00, 0b1110, 0b1111]

    encoder = HuffmanEncoder(8, 4, lsb_first=True)
    encoder.import_counts([4, 4, 4, 4, 4, 8, 2, 2])

    assert encoder.lengths == [3, 3, 3, 3, 3, 2, 4, 4]
    assert encoder.codes == [0b010, 0b110, 0b001, 0b101, 0b011, 0b00, 0b0111, 0b1111]


def test_huffman_encoder_import_counts_max_bits() -> None:
    """Test whether the code lengths are limited to the maximum length of a code, and still describe a complete tree."""
    counts = [1, 1, 2, 3, 5, 8, 13, 21, 34, 55]

    encoder = HuffmanEncoder(10, 9)
    encoder.import_counts(counts)
    assert encoder.lengths == [9, 9, 8, 7, 6, 5, 4, 3, 2, 1]

    encoder = HuffmanEncoder(10, 5)
    encoder.import_counts(counts)
    assert encoder.lengths == [5, 5, 5, 5, 4, 4, 3, 3, 2, 2]

    # The decoder only accepts complete trees
    HuffmanDecoder(10, 5).import_lengths(encoder.lengths)


def test_huffman_encoder_import_counts_single_code() -> None:
    """Test whether a single used symbol gets a code of one bit."""
    encoder = HuffmanEncoder(4, 2)
    encoder.import_counts([0, 0, 7, 0])

    assert encoder.lengths == [0, 0, 1, 0]
    assert encoder.codes == [0, 0, 0, 0]


def test_huffman_encoder_import_counts_invalid() -> None:
    """Test whether counts that don't fit the alphabet or the maximum code length raise an error."""
    encoder = HuffmanEncoder(4, 2)

    with pytest.raises(ValueError, match=r"^Invalid number of Huffman symbol counts$"):
        encoder.import_counts([1, 1])

    # Four symbols don't fit in codes of one bit
    with pytest.raises(ValueError, match=r"^Too many Huffman symbols for the maximum code length$"):
        HuffmanEncoder(4, 1).import_counts([1, 1, 1, 1])
