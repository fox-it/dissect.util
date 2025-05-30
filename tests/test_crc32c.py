from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.util import crc32c

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture


@pytest.mark.parametrize(
    ("data", "value", "expected"),
    [
        (b"hello, world!", 0, 0xCE8F3C63),
        (b"hello, world!", 0x12345678, 0x30663976),
        (b"", 0x12345678, 0x12345678),
        # https://tools.ietf.org/html/rfc3720#appendix-B.4
        # Empty
        (b"", 0, 0),
        # All zeroes
        (b"\x00" * 32, 0, 0x8A9136AA),
        # All ones
        (b"\xff" * 32, 0, 0x62A8AB43),
        # Incrementing
        (bytes(range(32)), 0, 0x46DD794E),
        # Decrementing
        (bytes(reversed(range(32))), 0, 0x113FDB5C),
    ],
)
def test_crc32c(data: bytes, value: int, expected: int) -> None:
    assert crc32c.crc32c(data, value) == expected


@pytest.mark.benchmark
def test_crc32c_benchmark(benchmark: BenchmarkFixture) -> None:
    benchmark(crc32c.crc32c, b"hello, world!", 0)
