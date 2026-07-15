from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

import pytest

from dissect.util.compression import lzxpress9

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture


# Raw XPRESS9 blocks (ESE 5-byte record header stripped) from the MIT ESE C
# reference encoder, the same code esent.dll links. Session signature is
# normalized to 0x12345678; the decoder accepts any valid signature.
PARAMS = (
    ("data", "size", "digest"),
    [
        pytest.param(
            "2ad7864e68010000d00200001b00060000000000eeadd4ba0000000015cc7f96000000e0c28229028e5c5932668d801127f6"
            "dcd92160c69e0702565cd972e08c803d37a69c107061c114011b86bc782260c29e39ba1addfe6d6f",
            360,
            "0c698b10ca43e8c4ad7225fc3fa3df99373cf62c4831b702f6e1f2b5d3601683",
            id="fox",
        ),
        pytest.param(
            "2ad7864ee8030000470100001b0006000000000043718bbc0000000012e14ffa000000000020fca33b",
            1000,
            "541b3e9daa09b20bf85fa273e5cbd3e80185aa4ec298e765db87742b70138a53",
            id="zeros",
        ),
        pytest.param(
            "2ad7864e480e0000030400004101060000000000cea7f001000000005ec0066e000020c266a6000040dcc56e12be7b5be118"
            "5559d57fe7dbc9d6e475a63af30600701fc17d040000466aa415fe0e710c9f016bf88443d64e48123a775f682f68b42d5945"
            "83b84167ea52bd351abefc4512b547cac437c6eb197fd5edfe789e9700",
            3656,
            "98aa38df85425a9709e9cdb479eddeb556a20583403681eb198d2ee82184c5ad",
            id="paragraph",
        ),
    ],
)

INPUT = b"the quick brown fox jumps over the lazy dog. " * 8
COMPRESSED = (
    "2ad7864e68010000cd0200001b000600000000007856341200000000c140bd45000000e0c28229028e5c5932668d801127f6dcd9"
    "2160c69e0702565cd972e08c803d37a69c107061c114011b86bc782260c29e393a04eddf050d"
)


@pytest.mark.parametrize(*PARAMS)
def test_lzxpress9_decompress(data: str, size: int, digest: str) -> None:
    assert hashlib.sha256(lzxpress9.decompress(bytes.fromhex(data))).hexdigest() == digest


@pytest.mark.parametrize(*PARAMS)
def test_lzxpress9_decompressed_size(data: str, size: int, digest: str) -> None:
    assert lzxpress9.decompressed_size(bytes.fromhex(data)) == size


def test_lzxpress9_compress() -> None:
    assert lzxpress9.decompress(lzxpress9.compress(INPUT)) == INPUT
    assert lzxpress9.compress(INPUT) == bytes.fromhex(COMPRESSED)


@pytest.mark.benchmark
@pytest.mark.parametrize(*PARAMS)
def test_benchmark_lzxpress9_decompress(data: str, size: int, digest: str, benchmark: BenchmarkFixture) -> None:
    assert hashlib.sha256(benchmark(lzxpress9.decompress, bytes.fromhex(data))).hexdigest() == digest


@pytest.mark.benchmark
def test_benchmark_lzxpress9_compress(benchmark: BenchmarkFixture) -> None:
    assert benchmark(lzxpress9.compress, INPUT) == bytes.fromhex(COMPRESSED)
