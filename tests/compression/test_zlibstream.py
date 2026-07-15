from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

import pytest

from dissect.util.compression import zlibstream

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture


# ZLIB stream of the 4096-byte A-Z pattern, from ntdll RtlCompressBuffer
# (COMPRESSION_FORMAT_ZLIB, 0x0008) on Win11 Build 26100.
GOLD = (
    "7801737276717573f7f0f4f2f6f1f5f30f080c0a0e090d0b8f888c72741a95190d83d174309a1746cb83d13271b45e18ad1b47db"
    "07a36da4d176e2685b79b4bf30da331aed190d939e110004d2d7f7"
)
GOLD_DIGEST = "45508be868dafa697653cbc4cc934b0ce5266eb7e87a5a9ac8fc8005ecc03189"

INPUT = b"the quick brown fox jumps over the lazy dog. " * 8
COMPRESSED = (
    "78012bc94855282ccd4cce56482aca2fcf5348cbaf50c82acd2d2856c82f4b2d5228014ae72456552aa4e4a7eb8179a38ac90a0d002fc08239"
)


def test_zlibstream_decompress() -> None:
    assert hashlib.sha256(zlibstream.decompress(bytes.fromhex(GOLD))).hexdigest() == GOLD_DIGEST


def test_zlibstream_compress() -> None:
    assert zlibstream.decompress(zlibstream.compress(INPUT)) == INPUT
    assert zlibstream.compress(INPUT) == bytes.fromhex(COMPRESSED)


@pytest.mark.benchmark
def test_benchmark_zlibstream_decompress(benchmark: BenchmarkFixture) -> None:
    assert hashlib.sha256(benchmark(zlibstream.decompress, bytes.fromhex(GOLD))).hexdigest() == GOLD_DIGEST


@pytest.mark.benchmark
def test_benchmark_zlibstream_compress(benchmark: BenchmarkFixture) -> None:
    assert benchmark(zlibstream.compress, INPUT) == bytes.fromhex(COMPRESSED)
