from __future__ import annotations

import hashlib
import zlib
from typing import TYPE_CHECKING

import pytest

from dissect.util.compression import deflate

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture


# Raw DEFLATE of the 4096-byte A-Z pattern, from ntdll RtlCompressBuffer
# (COMPRESSION_FORMAT_DEFLATE, 0x0007) on Win11 Build 26100.
GOLD = (
    "737276717573f7f0f4f2f6f1f5f30f080c0a0e090d0b8f888c72741a95190d83d174309a1746cb83d13271b45e18ad1b47db07a3"
    "6da4d176e2685b79b4bf30da331aed190d939e1100"
)
GOLD_DIGEST = "45508be868dafa697653cbc4cc934b0ce5266eb7e87a5a9ac8fc8005ecc03189"

INPUT = b"the quick brown fox jumps over the lazy dog. " * 8
COMPRESSED = "2bc94855282ccd4cce56482aca2fcf5348cbaf50c82acd2d2856c82f4b2d5228014ae72456552aa4e4a7eb8179a38ac90a0d00"


def test_deflate_decompress() -> None:
    assert hashlib.sha256(deflate.decompress(bytes.fromhex(GOLD))).hexdigest() == GOLD_DIGEST


def test_deflate_compress() -> None:
    assert deflate.decompress(deflate.compress(INPUT)) == INPUT
    assert deflate.compress(INPUT) == bytes.fromhex(COMPRESSED)


def test_deflate_decompress_max_size() -> None:
    compressed = deflate.compress(INPUT)
    assert deflate.decompress(compressed, max_size=len(INPUT)) == INPUT

    with pytest.raises(zlib.error):
        deflate.decompress(compressed, max_size=10)


@pytest.mark.benchmark
def test_benchmark_deflate_decompress(benchmark: BenchmarkFixture) -> None:
    assert hashlib.sha256(benchmark(deflate.decompress, bytes.fromhex(GOLD))).hexdigest() == GOLD_DIGEST


@pytest.mark.benchmark
def test_benchmark_deflate_compress(benchmark: BenchmarkFixture) -> None:
    assert benchmark(deflate.compress, INPUT) == bytes.fromhex(COMPRESSED)
