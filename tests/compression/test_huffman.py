from __future__ import annotations

import io

import pytest

from dissect.util.compression.huffman import HuffmanDecoder
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
