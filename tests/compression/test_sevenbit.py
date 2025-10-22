from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.util.compression import sevenbit

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture


def test_sevenbit_compress() -> None:
    result = sevenbit.compress(b"7-bit compression test string")
    target = bytes.fromhex("b796384d078ddf6db8bc3c9fa7df6e10bd3ca783e67479da7d06")
    assert result == target


@pytest.mark.benchmark
def test_benchmark_sevenbit_compress(benchmark: BenchmarkFixture) -> None:
    buf = b"7-bit compression test string"
    assert benchmark(sevenbit.compress, buf) == bytes.fromhex("b796384d078ddf6db8bc3c9fa7df6e10bd3ca783e67479da7d06")


def test_sevenbit_decompress() -> None:
    result = sevenbit.decompress(bytes.fromhex("b796384d078ddf6db8bc3c9fa7df6e10bd3ca783e67479da7d06"))
    target = b"7-bit compression test string"
    assert result == target


@pytest.mark.benchmark
def test_benchmark_sevenbit_decompress(benchmark: BenchmarkFixture) -> None:
    buf = bytes.fromhex("b796384d078ddf6db8bc3c9fa7df6e10bd3ca783e67479da7d06")
    assert benchmark(sevenbit.decompress, buf) == b"7-bit compression test string"


def test_sevenbit_decompress_wide() -> None:
    result = sevenbit.decompress(bytes.fromhex("b796384d078ddf6db8bc3c9fa7df6e10bd3ca783e67479da7d06"), wide=True)
    target = "7-bit compression test string".encode("utf-16-le")
    assert result == target


@pytest.mark.benchmark
def test_benchmark_sevenbit_decompress_wide(benchmark: BenchmarkFixture) -> None:
    buf = bytes.fromhex("b796384d078ddf6db8bc3c9fa7df6e10bd3ca783e67479da7d06")
    assert benchmark(sevenbit.decompress, buf, wide=True) == "7-bit compression test string".encode("utf-16-le")
