from __future__ import annotations

import hashlib
import io
from typing import TYPE_CHECKING

import pytest

from dissect.util.compression import lzxpress9

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture


# Compressed with the ESE C codec, using the parameters of ESE (4 MTF offsets, minimum match lengths of 4 and 2) unless
# noted otherwise
PARAMS = (
    ("data", "digest"),
    [
        pytest.param(
            "2ad7864e68010000d00200001b20060000000000c3c1383400000000c848e0aa000000e0c28229028e5c5932668d801127f6dcd92160c69e"
            "0702565cd972e08c803d37a69c107061c114011b86bc782260c29e39ba1addfe6d6f",
            "0c698b10ca43e8c4ad7225fc3fa3df99373cf62c4831b702f6e1f2b5d3601683",
            id="basic",
        ),
        pytest.param(
            "2ad7864e3c030000b50500003e41060000000000c3c1383400000000acf843c80000201792cd000040dc6d70f64d3ef64c526952b9f37aa6"
            "b949fbda79b7fd53000052b51f0500c0656e3a744539fab4b9119a10679ed0e608b664d686745d1a4dc71334cd03d7d27815f1906a7aaf00"
            "3f0859ca81b7a6108b661cc9af093a9649e3963c701ed08e563b2ae08ab5995a8ea459057a69fcfab798691cb8d157058c132c08076520d8"
            "d1551cb58720e96bee0397ff83dc13",
            "434a897070557bce1002b1b917c5bc8f208795515b96088115d3c9b9f2d063f0",
            id="huffman-tables",
        ),
        # No MTF offsets and a minimum match length of 3
        pytest.param(
            "2ad7864e3c030000bf0500003741000000000000c3c13834000000007377219fb990c8000040e465b0de9b5cde99a4d2a4b2e7744db393d3"
            "b673767b3300e06ac61f7dbb0000804b9facd06151917be913a60ea9f413526fc6e4f49890ac432d697b82457dc135d45e413c2492dec3c0"
            "374c86b261551762b01436e7c7d8518e228953767e6ed08c14d3765c1563d2f517f07d6e928feddbaf528ada821bebd8aeb0830161a3b443"
            "cac82a15319becba8e3e175cfe0f734f",
            "434a897070557bce1002b1b917c5bc8f208795515b96088115d3c9b9f2d063f0",
            id="mtf-0",
        ),
        # 2 MTF offsets and minimum match lengths of 3 and 3
        pytest.param(
            "2ad7864e3c030000ca0500004241090000000000c3c13834000000003ee2adbf00c88544060000222f83f5dee4f2ce249526953da76b9a9d"
            "9cb69db3db9b01005ccdf8a36f1700005cfa64850e8b8adc4b9f307548a59f907a3326a7c784641d6a49db132cea0baea1f60ae22191f41e"
            "06be6132940dabba1083a5b0393fc68e7214499cb2f3738366a498b6e3aa1893aebf80ef73937c6cdf7e9552d416dc58c776851d0c081ba5"
            "1d524656a988d964d775f4b9e0f27f987b02",
            "434a897070557bce1002b1b917c5bc8f208795515b96088115d3c9b9f2d063f0",
            id="mtf-2",
        ),
        # Contains an MTF offset directly after a match, which skips the first MTF offset
        pytest.param(
            "2ad7864e9b000000d00300001b20060000000000c3c13834000000001abbb80100000060c88e090226ec99570843764c103044c08c3d0f04"
            "8c38b1e7ceae4168108372e4ca9231eb06851557b61c3837692d302e2c98226088800d435e3cdbbc0c1b4a764c5a5e353850076905b40422"
            "b1e7c69453cb9b197b1e",
            "078eb9051c03467fc875b6bcb11cfc275c1378f2a41c534d15327e8d8d3fb851",
            id="mtf-after-match",
        ),
        # The block of basic, followed by a block with a long match from another session, renumbered as block 1
        pytest.param(
            "2ad7864e68010000d00200001b20060000000000c3c1383400000000c848e0aa000000e0c28229028e5c5932668d801127f6dcd92160c69e"
            "0702565cd972e08c803d37a69c107061c114011b86bc782260c29e39ba1addfe6d6f2ad7864efc010000840100001b20060000000000c3c1"
            "383401000000df9166ae00000060c88831131ee1eff70c19316602",
            "b50bd84986e2b4aec5a25393cb86c8bfa3ae84b2f0f114e1e12c9c4a7777767f",
            id="multi-block",
        ),
    ],
)


@pytest.mark.parametrize(*PARAMS)
def test_lzxpress9_decompress(data: str, digest: str) -> None:
    assert hashlib.sha256(lzxpress9.decompress(bytes.fromhex(data))).hexdigest() == digest
    assert hashlib.sha256(lzxpress9.decompress(io.BytesIO(bytes.fromhex(data)))).hexdigest() == digest


def test_lzxpress9_decompressed_size() -> None:
    """Test whether the decompressed size is read from the block headers."""
    buf = bytes.fromhex(PARAMS[1][5].values[0])
    assert lzxpress9.decompressed_size(buf) == len(lzxpress9.decompress(buf))


def test_lzxpress9_decompress_invalid() -> None:
    """Test whether invalid block headers and truncated blocks raise an error."""
    data = bytes.fromhex(PARAMS[1][0].values[0])

    with pytest.raises(ValueError, match=r"^Truncated XPRESS9 block header$"):
        lzxpress9.decompress(data[:31])

    with pytest.raises(ValueError, match=r"^Invalid XPRESS9 block magic$"):
        lzxpress9.decompress(b"\x00" + data[1:])

    # The session signature is covered by the header checksum
    with pytest.raises(ValueError, match=r"^Invalid XPRESS9 block header checksum$"):
        lzxpress9.decompress(data[:20] + b"\x00" + data[21:])

    with pytest.raises(ValueError, match=r"^Truncated XPRESS9 block$"):
        lzxpress9.decompress(data[:-1])

    # The second block of a session without the first
    with pytest.raises(ValueError, match=r"^Invalid XPRESS9 block sequence$"):
        lzxpress9.decompress(bytes.fromhex(PARAMS[1][5].values[0])[len(data) :])


COMPRESS_PARAMS = (
    ("data",),
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"a", id="single"),
        pytest.param(bytes(range(256)) * 300, id="repeated"),
        pytest.param(b"ABCD" * 25, id="medium_match"),
        pytest.param(b"ABCD" * 3 + b"E" + b"ABCD" * 300, id="long_match"),
        # The second ABCD is just out of reach of the first
        pytest.param(b"ABCD" + bytes(65533) + b"ABCD", id="far_match"),
        pytest.param(
            b"".join(hashlib.sha256(str(i).encode()).digest() for i in range(128)),
            id="incompressible",
        ),
    ],
)


@pytest.mark.parametrize(*COMPRESS_PARAMS)
def test_lzxpress9_compress(data: bytes) -> None:
    """Test whether compressing and decompressing data results in the original data."""
    assert lzxpress9.decompress(lzxpress9.compress(data)) == data
    assert lzxpress9.decompress(lzxpress9.compress(io.BytesIO(data))) == data


def test_lzxpress9_compress_reduces_size() -> None:
    """Test whether compressing data that has a lot of matches results in a smaller stream."""
    data = bytes(range(256)) * 128
    assert len(lzxpress9.compress(data)) < len(data)


@pytest.mark.benchmark
@pytest.mark.parametrize(*PARAMS)
def test_benchmark_lzxpress9_decompress(data: str, digest: str, benchmark: BenchmarkFixture) -> None:
    assert hashlib.sha256(benchmark(lzxpress9.decompress, bytes.fromhex(data))).hexdigest() == digest


@pytest.mark.benchmark
def test_benchmark_lzxpress9_compress(benchmark: BenchmarkFixture) -> None:
    assert hashlib.sha256(benchmark(lzxpress9.compress, bytes(range(256)) * 128)).hexdigest() == (
        "a48872ca02e4801ab9bdf283905234415aefa1013e2db4372b93e22d9e8adb8a"
    )
