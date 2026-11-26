from __future__ import annotations

import hashlib
import io
from typing import TYPE_CHECKING

import pytest

from dissect.util.compression import lzfse

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture


PARAMS = (
    ("data", "digest"),
    [
        pytest.param(
            "6276786e2c01000013000000c803616263f0fff005e163060000000000000062767824",
            "d9f5aeb06abebb3be3f38adec9a2e3b94228d52193be923eb4e24c9b56ee0930",
            id="basic",
        ),
        pytest.param(
            "62767832df360000a401200e000d0030b92c8bef56220070a50000003984"
            "70085f00b0000000383e59c0f1090000005fc027710c0000fc031c1f03c7"
            "700cc70000000000000000006c00003600000000005f07000000e7000000"
            "00100060418004120000e06338f9061e8067629dacdf013e836fe041f807"
            "be80fd14fc0e3fc29f704700000000000000000000000000000000000000"
            "000000000000000000000000000000000000101288d24318d9f446277ac6"
            "885a4b5dea360854e4c4616262d667f9f1ff53187e598fe2f5ddf7b768f4"
            "bcc1f6441b9e55e0d1be84b4b91544337f11c4d0d615068c79817f5d19f2"
            "09c83975cf9669b7f3d1024d9cc795e8ac449090696a7660585fac1a891c"
            "40557bb46c1b62a35ab2608d574e82ba9f3956d0f811370c78d69b24240f"
            "fd80ec4eccb6dc1e7f1c6f2f276a71e9c73183844c3dce83088eeed6c77c"
            "3e35316f414db430fcd2e22d0c07998d601addd5907f852df080386fe69e"
            "b78675198704b4bf5361caaf482e9333c6de0d46fbf87b4387fc6ac57116"
            "0300000000000000000066b7fffffff3fffa3ff7ff1fd2273e1f85c5f04f"
            "0f4945ab8462767824",
            "73d3dd96ca2e2f0144a117019256d770ee7c6febeaee09b24956c723ae22b529",
            id="large",
        ),
    ],
)


@pytest.mark.parametrize(*PARAMS)
def test_lzfse_decompress(data: str, digest: str) -> None:
    assert hashlib.sha256(lzfse.decompress(bytes.fromhex(data))).hexdigest() == digest


@pytest.mark.parametrize(
    "header",
    [
        # 20 literals and 10001 L, M, D values
        pytest.param("62767832220000001400a00000112720", id="matches"),
        # 40004 literals and 1 L, M, D value
        pytest.param("6276783222000000449ca00000010020", id="literals"),
    ],
)
def test_lzfse_decompress_block_limits(header: str) -> None:
    """Test whether a block with more literals or L, M, D values than the reference decoder allows raises an error."""
    # The rest of a block of the compressed data from 2 times b"Kusjes, van SRT!\n"
    data = (
        "9f81ee37bb0900609700000000000000000000008f0200000000f0280000003c3a00000000000000000000000000f0870000f01b0000"
        "000000f04dfc060000f01b00000000000000c06f0000bfc16ff01b000000fc06c06f00f01b00bf01c037c16ff01b0000000000000000"
        "0000000000000000000000000000000000000000000000000000000044042b473d693f320200000000000000002562767824"
    )
    assert lzfse.decompress(bytes.fromhex("62767832220000001400a00000010020" + data)) == b"Kusjes, van SRT!\n" * 2

    with pytest.raises(ValueError, match=r"^Invalid LZFSE block header$"):
        lzfse.decompress(bytes.fromhex(header + data))


COMPRESS_PARAMS = (
    ("data",),
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"Kusjes, van SRT!\n", id="literal"),
        pytest.param(bytes(range(256)) * 128, id="repeated"),
        pytest.param(b" ".join(b"%x" % (i * i % 1009) for i in range(5000)), id="text"),
        # A block has at most 40000 literals, the matches in the next block refer back into it
        pytest.param(b"".join(hashlib.sha256(str(i).encode()).digest() for i in range(1300)) * 2, id="literals"),
        # A block has at most 10000 L, M, D values
        pytest.param(b"".join(b"%5d" % i for i in range(12000)), id="matches"),
        # The second ABCD is just out of reach of the first
        pytest.param(b"ABCD" + bytes(262136) + b"ABCD" + bytes(12), id="far_match"),
        pytest.param(
            b"".join(hashlib.sha256(str(i).encode()).digest() for i in range(300)),
            id="incompressible",
        ),
    ],
)


@pytest.mark.parametrize(*COMPRESS_PARAMS)
def test_lzfse_compress(data: bytes) -> None:
    """Test whether compressing and decompressing data results in the original data."""
    assert lzfse.decompress(lzfse.compress(data)) == data
    assert lzfse.decompress(lzfse.compress(io.BytesIO(data))) == data


def test_lzfse_compress_reduces_size() -> None:
    """Test whether compressing data that has a lot of matches results in a smaller stream."""
    data = bytes(range(256)) * 128
    assert len(lzfse.compress(data)) < len(data)


@pytest.mark.benchmark
@pytest.mark.parametrize(*PARAMS)
def test_benchmark_lzfse_decompress(data: str, digest: str, benchmark: BenchmarkFixture) -> None:
    assert hashlib.sha256(benchmark(lzfse.decompress, bytes.fromhex(data))).hexdigest() == digest


@pytest.mark.benchmark
def test_benchmark_lzfse_compress(benchmark: BenchmarkFixture) -> None:
    assert hashlib.sha256(benchmark(lzfse.compress, bytes(range(256)) * 128)).hexdigest() == (
        "3763461362290934eb8a30cdf79e3544853e03619a0463eef594f1066d0a777c"
    )
