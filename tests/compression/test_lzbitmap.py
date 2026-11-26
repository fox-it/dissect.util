from __future__ import annotations

import hashlib
import io
from typing import TYPE_CHECKING

import pytest

from dissect.util.compression import lzbitmap

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture


PARAMS = (
    ("data", "digest"),
    [
        pytest.param(
            "5a424d093100002b0000536d616c6c2066696c657320646f6e2774206765"
            "7420636f6d7072657373656420617420616c6c2e2e2e0a060000000000",
            "8c929efb5fd28b5b82385b67b408f5e775a4756d7cc6373eebddb8668343ad40",
            id="uncompressed",
        ),
        pytest.param(
            "5a424d092d0000a0000018000018000018000061616161616161617835ef"
            "340f0000f10f00000000000000000000000000060000000000",
            "ef56118ff333a8bfeffc346c4987a1a178762570b3eb1d704a2c1e9b3a877561",
            id="small",
        ),
        pytest.param(
            "5a424d09d80100df36002301005001007601004c6f72656d20697073756d"
            "20646f6c6f722073742061657420636e7365636574757220616469706973"
            "696e67656c69742e517573716566617563627520657820736170656e7661"
            "6570656c6c6e6573656d6c61637261496e20696475727573206d69707269"
            "74656c757364206f76616c7354656d7075206c656f7561656e6561646469"
            "6d206e2074656d706f72506c6e7276697675736672696c61206c636e636d"
            "657473626962656e64756d67657461732e496c696d6173206e6c6d616c75"
            "64616c696e616e746567726e6e63707365722e5574206864726572697473"
            "6d7072766c637373207074656e74747469736f6f73712e41646c696f7261"
            "6f7175657465727562696f74726370746f686d6f732e0a0a4c0d2c341b41"
            "3e26113c5f6e805b6b7c65529d967ec4b310edb922ca7b1deca5faf4434a"
            "fbfa52fb8272b2ffb7016f7fcbc1b9f1373af99e3eb4e94fa9b3bafe39d3"
            "6959add6f36b55eecdb59d2ec3d1d029fc0055a9cbed016111718114103f"
            "480147110116011040f125f3ffffffffffffffffffffffffffffffffffff"
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            "ffffffffffffffff1f002cf68f57d9c576d73bfd7cd3d756000006000000"
            "0000",
            "73d3dd96ca2e2f0144a117019256d770ee7c6febeaee09b24956c723ae22b529",
            id="large",
        ),
    ],
)


@pytest.mark.parametrize(*PARAMS)
def test_lzbitmap_decompress(data: str, digest: str) -> None:
    assert hashlib.sha256(lzbitmap.decompress(bytes.fromhex(data))).hexdigest() == digest


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        # libzbitmap ends the nibbles right after the last bitmap
        pytest.param(
            "5a424d093400002f00001f00002000002000006162636465666768696a6162636465660a44353300fc03100000000000000000000000"
            "0000060000000000",
            b"abcdefghij" * 4 + b"abcdefg",
            id="end",
        ),
        # A padding nibble of 0xF after the last bitmap, which isn't a repeat count
        pytest.param(
            "5a424d092c00002800001800001800001800006162636465666768583433f500fc030800000000000000000000000000060000000000",
            b"abcdefgh" * 4 + b"abcdefgX",
            id="padding",
        ),
    ],
)
def test_lzbitmap_decompress_last_bitmap(data: str, expected: bytes) -> None:
    """Test whether the last bitmap of a chunk is read without a repeat count, like libzbitmap does."""
    assert lzbitmap.decompress(bytes.fromhex(data)) == expected


def test_lzbitmap_decompress_repeat_past_end() -> None:
    """Test whether the repeats of a bitmap that run past the end of the chunk are ignored, like libzbitmap does."""
    # A literal bitmap followed by a bitmap that is repeated 20 times, for a chunk that has 19 more groups of 8 bytes
    data = "5a424d092b0000a00000170000170000170000616263646566676834ff0100fc030000000000000000000000000000060000000000"
    assert lzbitmap.decompress(bytes.fromhex(data)) == b"abcdefgh" * 20


def test_lzbitmap_decompress_end_of_stream() -> None:
    """Test whether decompressing stops at the chunk that marks the end of the stream."""
    # A stored chunk of abc, the end of the stream, and a stored chunk of def after it
    data = bytes.fromhex("5a424d09 090000030000616263 060000000000 090000030000646566")
    assert lzbitmap.decompress(data) == b"abc"


COMPRESS_PARAMS = (
    ("data",),
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"Kusjes, van SRT!\n", id="literal"),
        pytest.param(bytes(range(256)) * 128, id="repeated"),
        pytest.param(b" ".join(b"%x" % (i * i % 1009) for i in range(5000)), id="text"),
        # A chunk that compresses to the size of a stored chunk would be mistaken for one, so it's stored
        pytest.param(b"abcdefghij" * 4 + b"abcdef", id="stored_size"),
        # Chunks are at most 32 KiB, matches can refer back into a previous chunk
        pytest.param(bytes(range(256)) * 300, id="chunks"),
        # The second ABCD is just out of reach of the first
        pytest.param(b"ABCD" + bytes(65532) + b"ABCD" + bytes(12), id="far_match"),
        # Chunks that don't get smaller when compressed are stored uncompressed
        pytest.param(
            b"".join(hashlib.sha256(str(i).encode()).digest() for i in range(300)),
            id="incompressible",
        ),
    ],
)


@pytest.mark.parametrize(*COMPRESS_PARAMS)
def test_lzbitmap_compress(data: bytes) -> None:
    """Test whether compressing and decompressing data results in the original data."""
    assert lzbitmap.decompress(lzbitmap.compress(data)) == data
    assert lzbitmap.decompress(lzbitmap.compress(io.BytesIO(data))) == data


def test_lzbitmap_compress_reduces_size() -> None:
    """Test whether compressing data that has a lot of matches results in a smaller stream."""
    data = bytes(range(256)) * 128
    assert len(lzbitmap.compress(data)) < len(data)


@pytest.mark.benchmark
@pytest.mark.parametrize(*PARAMS)
def test_benchmark_lzbitmap_decompress(data: str, digest: str, benchmark: BenchmarkFixture) -> None:
    assert hashlib.sha256(benchmark(lzbitmap.decompress, bytes.fromhex(data))).hexdigest() == digest


@pytest.mark.benchmark
def test_benchmark_lzbitmap_compress(benchmark: BenchmarkFixture) -> None:
    assert hashlib.sha256(benchmark(lzbitmap.compress, bytes(range(256)) * 128)).hexdigest() == (
        "7de14e35e719e48387fb65348023b82da2d041c539a5bee92241ac917d8d3621"
    )
