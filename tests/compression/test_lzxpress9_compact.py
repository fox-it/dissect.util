from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

import pytest

from dissect.util.compression import lzxpress9_compact
from dissect.util.exceptions import CorruptDataError

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture


# Raw compact XPRESS9 streams from ntdll RtlCompressBuffer(0x0005) on
# Server 2022 Build 20348. All decompress to the same 4096-byte A-Z pattern.
PARAMS = (
    ("data", "digest"),
    [
        pytest.param(
            "10e539c007404a0000a000a0f86783038941f998",
            "ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
            id="zeros_4096",
        ),
        pytest.param(
            "10e539c007404a0000a040b0f8678303e9517205",
            "6896d9ea3f73a4434f5832bc65714e7d066f177373f36f34dc8a6f735daa41b1",
            id="allA_4096",
        ),
        pytest.param(
            "10e539c007403f0000a000a0785a67ebc803",
            "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
            id="zeros_64",
        ),
        pytest.param(
            "10e539c00740540000a0a08a6af9cf0507021fea46",
            "116109c6e03f7d2cef4c67aff339970054357a2c75e3bb90f9adc388c0a1ffdd",
            id="alt_AA55_4096",
        ),
    ],
)

# Gold vector: 4096-byte A-Z pattern compressed with format 0x0005.
# Byte-identical across Server 2022 (Build 20348) and Server 2025 (Build 26100).
GOLD = (
    "10e539c007402f0100a040883011a2c4889320498a3419b2e4c853a048893215"
    "aad4a8d3a0498b60f3cfed56dc7a8d3d"
)
GOLD_DIGEST = "45508be868dafa697653cbc4cc934b0ce5266eb7e87a5a9ac8fc8005ecc03189"

INPUT = b"the quick brown fox jumps over the lazy dog. " * 8


@pytest.mark.parametrize(*PARAMS)
def test_lzxpress9_compact_decompress(data: str, digest: str) -> None:
    assert hashlib.sha256(lzxpress9_compact.decompress(bytes.fromhex(data))).hexdigest() == digest


def test_lzxpress9_compact_decompress_gold() -> None:
    assert hashlib.sha256(lzxpress9_compact.decompress(bytes.fromhex(GOLD))).hexdigest() == GOLD_DIGEST


def test_lzxpress9_compact_decompress_uncompressed() -> None:
    comp = bytes.fromhex("10e539c00740280000800051537d52")
    assert lzxpress9_compact.decompress(comp) == b"\x00"


def test_lzxpress9_compact_decompress_skip_verify() -> None:
    assert hashlib.sha256(lzxpress9_compact.decompress(bytes.fromhex(GOLD), verify=False)).hexdigest() == GOLD_DIGEST


def test_lzxpress9_compact_decompress_bad_magic() -> None:
    bad = b"\x00\x00\x00\x00" + bytes.fromhex(GOLD)[4:]
    with pytest.raises(CorruptDataError, match="magic"):
        lzxpress9_compact.decompress(bad)


def test_lzxpress9_compact_decompress_truncated() -> None:
    with pytest.raises(CorruptDataError, match="too short"):
        lzxpress9_compact.decompress(b"\x10\xe5\x39\xc0")


def test_lzxpress9_compact_compress() -> None:
    assert lzxpress9_compact.decompress(lzxpress9_compact.compress(INPUT)) == INPUT


@pytest.mark.benchmark
def test_benchmark_lzxpress9_compact_decompress(benchmark: BenchmarkFixture) -> None:
    assert hashlib.sha256(benchmark(lzxpress9_compact.decompress, bytes.fromhex(GOLD))).hexdigest() == GOLD_DIGEST


@pytest.mark.benchmark
def test_benchmark_lzxpress9_compact_compress(benchmark: BenchmarkFixture) -> None:
    result = benchmark(lzxpress9_compact.compress, INPUT)
    assert lzxpress9_compact.decompress(result) == INPUT
