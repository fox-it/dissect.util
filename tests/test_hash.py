from __future__ import annotations

import random
import zlib
from typing import TYPE_CHECKING, Any

import pytest

from dissect.util.hash import crc32, jenkins

if TYPE_CHECKING:
    from types import ModuleType

    from pytest_benchmark.fixture import BenchmarkFixture


def test_crc32(crc32c: ModuleType) -> None:
    assert crc32.crc32(b"123456789") == 0xCBF43926
    assert crc32.crc32(b"123456789", polynomial=0x82F63B78) == crc32c.crc32c(b"123456789")


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


@pytest.mark.parametrize("source_type", [bytes, bytearray, memoryview])
def test_crc32c_source_types(crc32c: ModuleType, source_type: type) -> None:
    assert crc32c.crc32c(source_type(bytes(range(32))), 0) == 0x46DD794E
    assert crc32c.update(0x12345678, source_type(b"hello, world!")) == 0x30663976


@pytest.mark.benchmark
def test_crc32c_benchmark(crc32c: ModuleType, benchmark: BenchmarkFixture) -> None:
    benchmark(crc32c.crc32c, b"hello, world!", 0)


@pytest.mark.benchmark
def test_crc32c_benchmark_page(crc32c: ModuleType, benchmark: BenchmarkFixture) -> None:
    # A 4 KiB page, as in the TIBX archives of dissect.archive
    assert benchmark(crc32c.crc32c, bytes(range(256)) * 16, 0) == 0x9C71FE32


@pytest.mark.parametrize(
    ("data", "value", "expected"),
    [
        (b"123456789", 0, 0xAE8B14860A799888),
        (b"", 0, 0),
        (b"\x00" * 32, 0, 0xCF3473434D4ECF3B),
        (b"hello, world!", 0x123456789ABCDEF0, 0x96270A5EF700596F),
    ],
)
def test_crc64c(crc64c: ModuleType, data: bytes, value: int, expected: int) -> None:
    assert crc64c.crc64c(data, value) == expected


@pytest.mark.parametrize("source_type", [bytes, bytearray, memoryview])
def test_crc64c_source_types(crc64c: ModuleType, source_type: type) -> None:
    assert crc64c.crc64c(source_type(b"123456789"), 0) == 0xAE8B14860A799888
    assert crc64c.update(0x123456789ABCDEF0, source_type(b"hello, world!")) == 0x96270A5EF700596F


@pytest.mark.benchmark
def test_crc64c_benchmark(crc64c: ModuleType, benchmark: BenchmarkFixture) -> None:
    benchmark(crc64c.crc64c, b"hello, world!", 0)


@pytest.mark.parametrize(
    ("data", "value", "expected"),
    [
        (b"123456789", 0, 0xE9C6D914C4B8D9CA),
        (b"", 0, 0),
        (b"", 0x123456789ABCDEF0, 0x123456789ABCDEF0),
        (b"6789", 0xF0758513239C7E0D, 0xE9C6D914C4B8D9CA),
    ],
)
def test_crc64_redis(crc64_redis: ModuleType, data: bytes, value: int, expected: int) -> None:
    assert crc64_redis.crc64_redis(data, value) == expected
    assert crc64_redis.update(value, data) == expected


@pytest.mark.benchmark
def test_crc64_redis_benchmark(crc64_redis: ModuleType, benchmark: BenchmarkFixture) -> None:
    benchmark(crc64_redis.crc64_redis, b"hello, world!", 0)


# Parameters and check values from the CRC catalogue: https://reveng.sourceforge.io/crc-catalogue/
CRC_CATALOGUE = [
    # (name, width, poly, init, xorout, reflected, check)
    ("CRC-32/ISO-HDLC", 32, 0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, True, 0xCBF43926),
    ("CRC-32/ISCSI", 32, 0x1EDC6F41, 0xFFFFFFFF, 0xFFFFFFFF, True, 0xE3069283),
    ("CRC-32/JAMCRC", 32, 0x04C11DB7, 0xFFFFFFFF, 0x00000000, True, 0x340BC6D9),
    ("CRC-32/BZIP2", 32, 0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, False, 0xFC891918),
    ("CRC-32/MPEG-2", 32, 0x04C11DB7, 0xFFFFFFFF, 0x00000000, False, 0x0376E6E7),
    ("CRC-64/ECMA-182", 64, 0x42F0E1EBA9EA3693, 0, 0, False, 0x6C40DF5F0B497347),
    ("CRC-64/WE", 64, 0x42F0E1EBA9EA3693, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, False, 0x62EC59E3F1A4F00A),
    ("CRC-64/XZ", 64, 0x42F0E1EBA9EA3693, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, True, 0x995DC9BBDF1939FA),
    ("CRC-64/GO-ISO", 64, 0x000000000000001B, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, True, 0xB90956C775A41001),
    ("CRC-64/NVME", 64, 0xAD93D23594C93659, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, True, 0xAE8B14860A799888),
    ("CRC-64/REDIS", 64, 0xAD93D23594C935A9, 0, 0, True, 0xE9C6D914C4B8D9CA),
]


def _make_crc(crc: ModuleType, width: int, poly: int, init: int, xorout: int, reflected: bool) -> Any:
    cls = crc.Crc32 if width == 32 else crc.Crc64
    return cls(poly, init=init, xorout=xorout, reflected=reflected)


@pytest.mark.parametrize(
    ("width", "poly", "init", "xorout", "reflected", "check"),
    [pytest.param(*params, id=name) for name, *params in CRC_CATALOGUE],
)
def test_crc_catalogue(
    crc: ModuleType, width: int, poly: int, init: int, xorout: int, reflected: bool, check: int
) -> None:
    c = _make_crc(crc, width, poly, init, xorout, reflected)

    assert c(b"123456789") == check
    assert c(b"") == init ^ xorout
    # Chunked updates compose
    assert c(b"6789", c(b"12345")) == check
    assert c.update(c(b"12345"), b"6789") == check
    assert c(bytearray(b"123456789")) == check

    assert (c.poly, c.init, c.xorout, c.reflected) == (poly, init, xorout, reflected)
    assert len(c.table) == 256


@pytest.mark.parametrize(
    ("width", "poly", "init", "xorout", "reflected", "check"),
    [pytest.param(*params, id=name) for name, *params in CRC_CATALOGUE],
)
def test_crc_native_matches_python(width: int, poly: int, init: int, xorout: int, reflected: bool, check: int) -> None:
    from dissect.util import hash

    if hash.crc_native is None:
        pytest.skip("_native module is unavailable")

    native = _make_crc(hash.crc_native, width, poly, init, xorout, reflected)
    python = _make_crc(hash.crc_python, width, poly, init, xorout, reflected)

    assert native.table == python.table

    rng = random.Random(width ^ poly)  # noqa: S311
    for size in (0, 1, 7, 8, 255, 4096, 70000):  # 70000 crosses the native GIL release threshold
        data = rng.randbytes(size)
        assert native(data) == python(data)
        assert native(data, 0x1234) == python(data, 0x1234)


def test_crc_matches_existing(crc: ModuleType, crc32c: ModuleType, crc64c: ModuleType) -> None:
    data = random.Random(1).randbytes(1000)  # noqa: S311

    assert crc.Crc32(0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF)(data) == zlib.crc32(data)
    assert crc.Crc32(0x1EDC6F41, 0xFFFFFFFF, 0xFFFFFFFF)(data) == crc32c.crc32c(data)
    assert crc.Crc64(0xAD93D23594C93659, 2**64 - 1, 2**64 - 1)(data) == crc64c.crc64c(data)


def test_crc_invalid_parameters() -> None:
    from dissect.util.hash import crc_python

    with pytest.raises(ValueError, match="32 bits"):
        crc_python.Crc32(0x1_0000_0000)


@pytest.mark.benchmark
def test_crc_benchmark(crc: ModuleType, benchmark: BenchmarkFixture) -> None:
    c = crc.Crc64(0xAD93D23594C935A9)
    benchmark(c, b"hello, world!")


def test_lookup8_remainder() -> None:
    ip = b"192.168.1.109"
    volume = b"/home/roel/nfstest"
    h1 = jenkins.lookup8(ip, 42)
    h2 = jenkins.lookup8(volume, h1)
    assert h2 == 5364432747070711354


def test_lookup8_full() -> None:
    h1 = jenkins.lookup8(b"Het implementeren van hashfuncties in Python is lastiger dan je zou denken,", 42)
    h2 = jenkins.lookup8(b"met name door de ontbrekende ondersteuning voor unsigned integer arithmetic", h1)
    assert h2 == 2809036171121327430


def test_lookup8_empty_key() -> None:
    assert jenkins.lookup8(b"", 666) == 8664614747486377173


@pytest.mark.benchmark
def test_lookup8_benchmark(benchmark: BenchmarkFixture) -> None:
    benchmark(jenkins.lookup8, b"hello, world!", 42)


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
    assert jenkins.lookup8_quads(key, 42) == 0x68175B25629F42F4


@pytest.mark.benchmark
def test_lookup8_quads_benchmark(benchmark: BenchmarkFixture) -> None:
    key = b"a" * 256
    benchmark(jenkins.lookup8_quads, key, 42)
