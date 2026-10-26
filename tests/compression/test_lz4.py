from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

import pytest

from dissect.util.exceptions import CorruptDataError

if TYPE_CHECKING:
    from types import ModuleType

    from pytest_benchmark.fixture import BenchmarkFixture


PARAMS = (
    ("data", "digest"),
    [
        pytest.param(
            "ff0c4c5a3420636f6d7072657373696f6e207465737420737472696e671b00db507472696e67",
            "5ec59b1b60247178b260e145ae888c318e1fa3ee4466cf0e145de8f24c4b1501",
            id="basic",
        ),
        pytest.param(
            "ffffa94c6f72656d20697073756d20646f6c6f722073697420616d657420636f"
            "6e73656374657475722061646970697363696e6720656c69742e205175697371"
            "75652066617563696275732065782073617069656e2076697461652070656c6c"
            "656e7465737175652073656d20706c6163657261742e20496e20696420637572"
            "737573206d69207072657469756d2074656c6c7573206475697320636f6e7661"
            "6c6c69732e2054656d707573206c656f2065752061656e65616e207365642064"
            "69616d2075726e612074656d706f722e2050756c76696e617220766976616d75"
            "73206672696e67696c6c61206c61637573206e6563206d657475732062696265"
            "6e64756d20656765737461732e20496163756c6973206d61737361206e69736c"
            "206d616c657375616461206c6163696e696120696e7465676572206e756e6320"
            "706f73756572652e2055742068656e6472657269742073656d7065722076656c"
            "20636c61737320617074656e742074616369746920736f63696f7371752e2041"
            "64206c69746f726120746f727175656e742070657220636f6e75626961206e6f"
            "7374726120696e636570746f732068696d656e61656f732e0a0ab701ffffffff"
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            "ffffffffffffffffffffffffffffffffff4550656f732e0a",
            "73d3dd96ca2e2f0144a117019256d770ee7c6febeaee09b24956c723ae22b529",
            id="large",
        ),
    ],
)


DICTIONARY_PARAMS = (
    ("data", "dictionary", "expected"),
    [
        pytest.param(
            "13540a001f3a3600182f2c207e00035072696e6721",
            b"LZ4 dictionary test string, shared between the dictionary and the data. ",
            b"The data: shared between the dictionary and the data, LZ4 dictionary test string!",
            id="basic",
        ),
        # A single match that starts in the dictionary and runs on into the output it is producing
        pytest.param(
            "0f060035a030313233343536373839",
            b"0123456789abcdef",
            b"abcdef" * 12 + b"0123456789",
            id="straddle",
        ),
        # A match offset is 16 bits, so only the last 64 KiB of a dictionary can be referenced
        pytest.param(
            "194110000032009f313620626974733a2062001c50656163682e",
            bytes(range(256)) * 300 + b"only the tail of a large dictionary is within reach of a match offset. ",
            b"A match offset is 16 bits: only the tail of a large dictionary is within reach.",
            id="large",
        ),
    ],
)


@pytest.mark.parametrize(*PARAMS)
def test_lz4_decompress(lz4: ModuleType, data: str, digest: str) -> None:
    assert hashlib.sha256(lz4.decompress(bytes.fromhex(data))).hexdigest() == digest

    # No dictionary and an empty dictionary are the same thing
    assert hashlib.sha256(lz4.decompress(bytes.fromhex(data), dictionary=None)).hexdigest() == digest
    assert hashlib.sha256(lz4.decompress(bytes.fromhex(data), dictionary=b"")).hexdigest() == digest


@pytest.mark.parametrize(*DICTIONARY_PARAMS)
def test_lz4_decompress_dictionary(lz4: ModuleType, data: str, dictionary: bytes, expected: bytes) -> None:
    assert lz4.decompress(bytes.fromhex(data), dictionary=dictionary) == expected
    assert lz4.decompress(bytes.fromhex(data), len(expected), dictionary=dictionary) == expected

    result = lz4.decompress(bytes.fromhex(data), len(expected), True, dictionary)
    assert isinstance(result, bytearray)
    assert result == expected

    # The dictionary may be a bytearray too, such as the output accumulated so far
    assert lz4.decompress(bytes.fromhex(data), dictionary=bytearray(dictionary)) == expected

    # Without its dictionary, the block refers back to data that is not there
    with pytest.raises((CorruptDataError, ValueError), match=r"[Oo]ffset"):
        lz4.decompress(bytes.fromhex(data))

    # The same goes for a dictionary that does not reach back far enough
    with pytest.raises((CorruptDataError, ValueError), match=r"[Oo]ffset"):
        lz4.decompress(bytes.fromhex(data), dictionary=dictionary[-1:])

    # The dictionary does not count towards the uncompressed size
    with pytest.raises((CorruptDataError, ValueError), match=r"too small|exceeds"):
        lz4.decompress(bytes.fromhex(data), len(expected) - 1, dictionary=dictionary)


def test_lz4_decompress_chain(lz4: ModuleType) -> None:
    # A chain of dependent blocks, each compressed against everything before it (LZ4_compress_fast_continue).
    # Decompressing with the output so far as the dictionary is what LZ4_decompress_safe_continue does.
    blocks = [
        "f020666972737420626c6f636b206f662074686520636861696e2c206e6f7468696e6720746f207265666572206261636b"
        "0e005f7965742e20380020507965742e20",
        "6f7365636f6e64390002012e0010723b00043200001d000f6900025061696e2e20",
        "4f746869724a002531616e6414000f8f0002506861696e2e",
    ]

    result = b""
    for block in blocks:
        result += lz4.decompress(bytes.fromhex(block), dictionary=result)

    assert result == (
        b"first block of the chain, nothing to refer back to yet. "
        b"first block of the chain, nothing to refer back to yet. "
        b"second block of the chain, referring back to the first block of the chain. "
        b"third block of the chain, referring back to the first block and the second block of the chain."
    )


@pytest.mark.benchmark
@pytest.mark.parametrize(*PARAMS)
def test_benchmark_lz4_decompress(lz4: ModuleType, data: str, digest: str, benchmark: BenchmarkFixture) -> None:
    assert hashlib.sha256(benchmark(lz4.decompress, bytes.fromhex(data))).hexdigest() == digest


@pytest.mark.benchmark
@pytest.mark.parametrize(*DICTIONARY_PARAMS)
def test_benchmark_lz4_decompress_dictionary(
    lz4: ModuleType, data: str, dictionary: bytes, expected: bytes, benchmark: BenchmarkFixture
) -> None:
    assert benchmark(lz4.decompress, bytes.fromhex(data), dictionary=dictionary) == expected
