from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.util.hash.jenkins import lookup8, lookup8_quads

if TYPE_CHECKING:
    from types import ModuleType

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
def test_crc32c(crc32c: ModuleType, data: bytes, value: int, expected: int) -> None:
    assert crc32c.crc32c(data, value) == expected


@pytest.mark.benchmark
def test_crc32c_benchmark(crc32c: ModuleType, benchmark: BenchmarkFixture) -> None:
    benchmark(crc32c.crc32c, b"hello, world!", 0)


def test_lookup8_remainder() -> None:
    ip = b"192.168.1.109"
    volume = b"/home/roel/nfstest"
    h1 = lookup8(ip, 42)
    h2 = lookup8(volume, h1)
    assert h2 == 5364432747070711354


def test_lookup8_full() -> None:
    h1 = lookup8(b"Het implementeren van hashfuncties in Python is lastiger dan je zou denken,", 42)
    h2 = lookup8(b"met name door de ontbrekende ondersteuning voor unsigned integer arithmetic", h1)
    assert h2 == 2809036171121327430


def test_lookup8_empty_key() -> None:
    assert lookup8(b"", 666) == 8664614747486377173


@pytest.mark.benchmark
def test_lookup8_benchmark(benchmark: BenchmarkFixture) -> None:
    benchmark(lookup8, b"hello, world!", 42)


def test_lookup8_quads() -> None:
    key = bytes.fromhex(
        "4b75736a65732076616e20535254203c330000000000000017b0618ec2759a73"
        "17b0618ec2759a7317b0618ec2759a7317b0618ec2759a7317b0618ec2759a73"
        "17b0618ec2759a7317b0618ec2759a7317b0618ec2759a7317b0618ec2759a73"
        "17b0618ec2759a7317b0618ec2759a7317b0618ec2759a7317b0618ec2759a73"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
    )
    assert lookup8_quads(key, 42) == 0x68175B25629F42F4


@pytest.mark.benchmark
def test_lookup8_quads_benchmark(benchmark: BenchmarkFixture) -> None:
    key = b"a" * 256
    benchmark(lookup8_quads, key, 42)
