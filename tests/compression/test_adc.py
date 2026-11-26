from __future__ import annotations

import hashlib
import io
from typing import TYPE_CHECKING

import pytest

from dissect.util.compression import adc

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture


PARAMS = (
    ("data", "digest"),
    [
        pytest.param(
            "80007f00007f00007f00007f00007f00007f000068001683feffffee00038001004a814d206e004f8155aa",
            "8f07c1fe1f936f1c90594be4773789af3f1c0bc5f117396d17641cb0c11992cc",
            id="basic",
        ),
        pytest.param(
            "a1ef57347c0000aa11aa1100306543ecacc720e4affaef7f4689d11236f2"
            "63affc28000c008127201008100f886400690073006b00200007866d0061"
            "006700652c207f00007f00007f00007f00007f00007f00007f00007f0000"
            "7f00007f00007f00007f00007f00007f00007f00007f00007f00007f0000"
            "7f00007f00007f00007f00007f00007f00007f00007f00007f00007f0000"
            "7f00007f00007f00007f00007f00007f00007f00007f00007f00007f0000"
            "7f00007f00007f00007f00007f00007f00007f00007f00007f00007f0000"
            "7f00007f00007f00007f00007f00007f00007f00007f00007f00007f0000"
            "7f00007f00007f00007f00007f00007f00007f00007f00007f00007f0000"
            "7f00007f00007f00007f00007f00007f00007f00007f00007f00007f0000"
            "7f00007f00007f00007f00007f00007f00007f00007f00007f00007f0000"
            "7f00007f00007f00007f00007f00007f00007f00007f00007f00007f0000"
            "7f00007f00007f00007f00007f00007f00007f00007f00007f00007f0000"
            "7f00007f00007f00007f00007f00007f00007f00007f00007f00007f0000"
            "7f00007f00007f00007f00007f00007f00007f00007f00007f00007f0000"
            "7f00007f00007f00007f00007f00007f00007f00007f00007f00007f0000"
            "7f00007f00007f00007f00007f00007f00007f00007f00007f00007f0000"
            "7f00007f00007f00007f00007f00007f00007f00007f00007f00007f0000"
            "7f00007f00007f00007f00007f00007f00007f00007f00007f00007f0000"
            "7f00007f00007f00007f00007f00007f00007f00007f00007f00007f0000"
            "7f00007f00007f00007f00007f00007f00007f00007f00007f00007f0000"
            "7f00007f00007f00007f00007f00007f00007f00007f00007f00007f0000"
            "7f00007f00007f00007f00007f00007f00007f00007f00007f00007f0000"
            "7f00007f00007f00007f00007f00007f00007f00007f00007f00007f0000"
            "7f00007f00007f00007f00007f00007f00007f00007f00007f00007f0000"
            "7f00007f00007f00007f00007f00007f00007f00007f00007f00007f0000"
            "7f00007f00007f00007f00007f00004a3fc7",
            "74faa5da44da54516026fe33c0e4a0eca261f02ea01bc1434143d77007ee57b1",
            id="large",
        ),
    ],
)


@pytest.mark.parametrize(*PARAMS)
def test_adc_decompress(data: str, digest: str) -> None:
    assert hashlib.sha256(adc.decompress(bytes.fromhex(data))).hexdigest() == digest


COMPRESS_PARAMS = (
    ("data",),
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"Kusjes, van SRT!\n", id="literal"),
        pytest.param(bytes(range(256)) * 128, id="repeated"),
        pytest.param(b" ".join(b"%x" % (i * i % 1009) for i in range(5000)), id="text"),
        # The second ABCD is just out of reach of the first
        pytest.param(b"ABCD" + bytes(65533) + b"ABCD" + bytes(12), id="far_match"),
        pytest.param(
            b"".join(hashlib.sha256(str(i).encode()).digest() for i in range(300)),
            id="incompressible",
        ),
    ],
)


@pytest.mark.parametrize(*COMPRESS_PARAMS)
def test_adc_compress(data: bytes) -> None:
    """Test whether compressing and decompressing data results in the original data."""
    assert adc.decompress(adc.compress(data)) == data
    assert adc.decompress(adc.compress(io.BytesIO(data))) == data


def test_adc_compress_reduces_size() -> None:
    """Test whether compressing data that has a lot of matches results in a smaller stream."""
    data = bytes(range(256)) * 128
    assert len(adc.compress(data)) < len(data)


@pytest.mark.benchmark
@pytest.mark.parametrize(*PARAMS)
def test_benchmark_adc_decompress(data: str, digest: str, benchmark: BenchmarkFixture) -> None:
    assert hashlib.sha256(benchmark(adc.decompress, bytes.fromhex(data))).hexdigest() == digest


@pytest.mark.benchmark
def test_benchmark_adc_compress(benchmark: BenchmarkFixture) -> None:
    assert hashlib.sha256(benchmark(adc.compress, bytes(range(256)) * 128)).hexdigest() == (
        "5c1f2a87cc1ce691b657aebf3d4533247b03697a91ba5b36a710591a7a45c4e2"
    )
