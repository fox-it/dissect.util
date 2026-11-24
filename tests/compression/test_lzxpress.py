from __future__ import annotations

import hashlib
import io
from typing import TYPE_CHECKING

import pytest

from dissect.util.compression import lzxpress

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture


PARAMS = (
    ("data", "digest"),
    [
        pytest.param(
            "ffff ff1f 6162 6317 000f ff26 01",
            "d9f5aeb06abebb3be3f38adec9a2e3b94228d52193be923eb4e24c9b56ee0930",
            id="basic",
        ),
        pytest.param(
            "000000004c6f72656d20697073756d20646f6c6f722073697420616d65742063"
            "6f6e7365000000006374657475722061646970697363696e6720656c69742e20"
            "51756973717565200000000066617563696275732065782073617069656e2076"
            "697461652070656c6c656e7401021050652a01731803706c6163657261d80149"
            "6e2069642063757273b8016d69207072657469f8030020006c749001880064d0"
            "02e10376616c6c69732e2054656d70b0006c656f2065752061656e65616e0480"
            "000020736564206469616d2075726e61207410016f722e2050756c76696e6172"
            "1804766100300c026d75732066729005696c6c6120e80378006e656320d80648"
            "00626962656e64756d20656765040200107374613803496163756c6973206d61"
            "737361206e69736c50006c6573756164f201696e100000086961206990066765"
            "72206e756e6320706f73756572652e20557420686802726572690080104474d0"
            "046d70651004656c20636c58022061707448082074616369746920736f63696f"
            "737108c11000752e204164206c69746f72f8056f7271751901c101636f6e7562"
            "50036e6f7374d800696e63ff3f00006570746f732068696d656e61656f732e0a"
            "0ab70d0fff2535",
            "73d3dd96ca2e2f0144a117019256d770ee7c6febeaee09b24956c723ae22b529",
            id="large",
        ),
    ],
)


@pytest.mark.parametrize(*PARAMS)
def test_lzxpress_decompress(data: str, digest: str) -> None:
    assert hashlib.sha256(lzxpress.decompress(bytes.fromhex(data))).hexdigest() == digest


def test_lzxpress_decompress_invalid_distance() -> None:
    # The first flag bit marks a match, which has nothing to refer back to yet
    with pytest.raises(ValueError, match="Invalid match distance"):
        lzxpress.decompress(bytes.fromhex("000000800000"))


@pytest.mark.parametrize(
    "data",
    [
        # Three of the four bytes of the flags
        pytest.param("000000", id="flags"),
        # Flags that mark a literal, but the literal is missing
        pytest.param("00000000", id="literal"),
    ],
)
def test_lzxpress_decompress_truncated(data: str) -> None:
    """Test whether input that ends halfway through an element raises an error."""
    with pytest.raises(ValueError, match=r"^Truncated LZXpress stream$"):
        lzxpress.decompress(bytes.fromhex(data))


@pytest.mark.parametrize(*PARAMS)
def test_lzxpress_decompress_size(data: str, digest: str) -> None:
    """Test whether decompressing stops at the decompressed size, also halfway through a match."""
    buf = bytes.fromhex(data)
    result = lzxpress.decompress(buf)

    assert hashlib.sha256(lzxpress.decompress(buf, len(result))).hexdigest() == digest
    assert lzxpress.decompress(buf, 100) == result[:100]

    # Data after the decompressed size isn't read, here it would be a match with an invalid distance
    assert lzxpress.decompress(buf + b"\xff\xff", len(result)) == result


COMPRESS_PARAMS = (
    ("data",),
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"Kusjes, van SRT!\n", id="literal"),
        pytest.param(b"\x00" * 70000, id="zeros"),
        pytest.param(bytes(range(256)) * 128, id="repeated"),
        # A match length of 280, which doesn't fit in the length byte, because a byte of 255 means that a word follows
        pytest.param(bytes(281), id="length_255"),
        pytest.param(b"ABCD" * 3 + b"E" + b"ABCD" * 300, id="long_match"),
        # The second ABCD is just out of reach of the first
        pytest.param(b"ABCD" + bytes(8189) + b"ABCD", id="far_match"),
        # Matches that share the nibble of their length
        pytest.param((b"A" * 30 + b"B") * 3, id="shared_nibble"),
        pytest.param(
            b"".join(hashlib.sha256(str(i).encode()).digest() for i in range(128)),
            id="incompressible",
        ),
    ],
)


@pytest.mark.parametrize(*COMPRESS_PARAMS)
def test_lzxpress_compress(data: bytes) -> None:
    """Test whether compressing and decompressing data results in the original data."""
    assert lzxpress.decompress(lzxpress.compress(data)) == data
    assert lzxpress.decompress(lzxpress.compress(io.BytesIO(data))) == data


def test_lzxpress_compress_example() -> None:
    """Test whether compressing the examples of [MS-XCA] section 3.1 results in the same data."""
    assert lzxpress.compress(b"abcdefghijklmnopqrstuvwxyz") == bytes.fromhex(
        "3f000000 6162636465666768696a6b6c6d6e6f707172737475767778797a"
    )
    assert lzxpress.compress(b"abc" * 100) == bytes.fromhex(PARAMS[1][0].values[0])


@pytest.mark.benchmark
@pytest.mark.parametrize(*PARAMS)
def test_benchmark_lzxpress_decompress(data: str, digest: str, benchmark: BenchmarkFixture) -> None:
    assert hashlib.sha256(benchmark(lzxpress.decompress, bytes.fromhex(data))).hexdigest() == digest


@pytest.mark.benchmark
def test_benchmark_lzxpress_compress(benchmark: BenchmarkFixture) -> None:
    assert hashlib.sha256(benchmark(lzxpress.compress, bytes(range(256)) * 128)).hexdigest() == (
        "82e54b6bb6cda404a432158acf8bce60c831defb876b101ff223aa300e050156"
    )
