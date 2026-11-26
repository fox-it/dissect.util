from __future__ import annotations

import hashlib
import io
from typing import TYPE_CHECKING

import pytest

from dissect.util.compression import lzvn

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture


PARAMS = (
    ("data", "digest"),
    [
        pytest.param(
            "c803616263f0fff005e1630600000000000000",
            "d9f5aeb06abebb3be3f38adec9a2e3b94228d52193be923eb4e24c9b56ee0930",
            id="basic",
        ),
        pytest.param(
            "e0514c6f72656d20697073756d20646f6c6f722073697420616d65742063"
            "6f6e73656374657475722061646970697363696e6720656c69742e205175"
            "69737175652066617563696275732065782073617069656e207669746165"
            "2070656c6c656e74651026406473e7706c6163657261003cea496e206964"
            "20637572730038e86d6920707265746900804033740012405b64087dec76"
            "616c6c69732e2054656d700017ed6c656f2065752061656e65616e0052eb"
            "64206469616d2075726e61003aee6d706f722e2050756c76696e61720084"
            "c03576616d80b36672e5696c6c6120007e0010e46e65632000dc000ae662"
            "6962656e640076e665676573746100684022490071eb206d61737361206e"
            "69736c000be66c6573756164103fe6696e6961206900d3e006676572206e"
            "756e6320706f73756572652e2055742068004ee5726572697408ed402270"
            "e676656c20636c004ce420617074010a80432074e8746920736f63696f01"
            "16e52e20416420014c80c06f72e46f7271750824083900fb806b7562e56e"
            "6f7374720872e003636570746f732068696d656e61656f732e0a0a39b7f0"
            "fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0"
            "fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0"
            "fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0"
            "fff0fff0fff0fff0fff01de3732e0a0600000000000000",
            "73d3dd96ca2e2f0144a117019256d770ee7c6febeaee09b24956c723ae22b529",
            id="large",
        ),
    ],
)


@pytest.mark.parametrize(*PARAMS)
def test_lzvn_decompress(data: str, digest: str) -> None:
    assert hashlib.sha256(lzvn.decompress(bytes.fromhex(data))).hexdigest() == digest


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        pytest.param("0600000000000000", b"", id="empty"),
        # A literal, a match of 3 bytes and a match of 2 bytes that reuses the distance
        pytest.param("e161 0001 f2 0600000000000000", b"aaaaaa", id="match"),
    ],
)
def test_lzvn_decompress_end_of_stream(data: str, expected: bytes) -> None:
    """Test whether the end of stream opcode also ends the stream after an opcode without literals."""
    assert lzvn.decompress(bytes.fromhex(data)) == expected


COMPRESS_PARAMS = (
    ("data",),
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"Kusjes, van SRT!\n", id="literal"),
        pytest.param(bytes(range(256)) * 128, id="repeated"),
        pytest.param(b" ".join(b"%x" % (i * i % 1009) for i in range(5000)), id="text"),
        # A match between 1536 and 16384 bytes away has an encoding with room for a longer match
        pytest.param(b"ZYXWVUTSRQPO" + bytes(range(256)) * 8 + b"ZYXWVUTSRQPO", id="medium_distance"),
        # The second ABCD is just out of reach of the first
        pytest.param(b"ABCD" + bytes(65532) + b"ABCD" + bytes(12), id="far_match"),
        pytest.param(
            b"".join(hashlib.sha256(str(i).encode()).digest() for i in range(300)),
            id="incompressible",
        ),
    ],
)


@pytest.mark.parametrize(*COMPRESS_PARAMS)
def test_lzvn_compress(data: bytes) -> None:
    """Test whether compressing and decompressing data results in the original data."""
    assert lzvn.decompress(lzvn.compress(data)) == data
    assert lzvn.decompress(lzvn.compress(io.BytesIO(data))) == data


def test_lzvn_compress_reduces_size() -> None:
    """Test whether compressing data that has a lot of matches results in a smaller stream."""
    data = bytes(range(256)) * 128
    assert len(lzvn.compress(data)) < len(data)


@pytest.mark.benchmark
@pytest.mark.parametrize(*PARAMS)
def test_benchmark_lzvn_decompress(data: str, digest: str, benchmark: BenchmarkFixture) -> None:
    assert hashlib.sha256(benchmark(lzvn.decompress, bytes.fromhex(data))).hexdigest() == digest


@pytest.mark.benchmark
def test_benchmark_lzvn_compress(benchmark: BenchmarkFixture) -> None:
    assert hashlib.sha256(benchmark(lzvn.compress, bytes(range(256)) * 128)).hexdigest() == (
        "2f889a1e472c8319890f316ed922bb9bf1b8c9ba84764831d0edf22b218a280f"
    )
