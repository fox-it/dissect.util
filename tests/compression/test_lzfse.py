from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

import pytest

from dissect.util.compression import lzfse

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture


@pytest.mark.parametrize(
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
def test_lzfse_decompress(data: str, digest: str) -> None:
    assert hashlib.sha256(lzfse.decompress(bytes.fromhex(data))).hexdigest() == digest


@pytest.mark.benchmark
def test_benchmark_lzfse_decompress(benchmark: BenchmarkFixture) -> None:
    buf = bytes.fromhex("6276786e2c01000013000000c803616263f0fff005e163060000000000000062767824")
    assert benchmark(lzfse.decompress, buf) == b"abc" * 100


@pytest.mark.benchmark
def test_benchmark_large_lzfse_decompress(benchmark: BenchmarkFixture) -> None:
    buf = bytes.fromhex(
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
        "0f4945ab8462767824"
    )
    assert (
        hashlib.sha256(benchmark(lzfse.decompress, buf)).hexdigest()
        == "73d3dd96ca2e2f0144a117019256d770ee7c6febeaee09b24956c723ae22b529"
    )
