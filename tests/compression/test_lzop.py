from __future__ import annotations

import hashlib
import io
from typing import TYPE_CHECKING

import pytest

from dissect.util.compression import lzop

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture


PARAMS = (
    ("data", "digest"),
    [
        pytest.param(
            "894c5a4f000d0a1a0a104020a00940010503000001000081a4699f2a5700"
            "00000005736d616c6c515206300000012c00000021884d72d90361626361"
            "626320f314000f6162636162636162636162636162636162631100000000"
            "0000",
            "d9f5aeb06abebb3be3f38adec9a2e3b94228d52193be923eb4e24c9b56ee0930",
            id="basic",
        ),
        pytest.param(
            "894c5a4f000d0a1a0a104020a00940010503000001000081a4699f2a6e00"
            "000000056c61726765521e0639000036df00000213975059030000b34c6f"
            "72656d20697073756d20646f6c6f722073697420616d657420636f6e7365"
            "6374657475722061646970697363696e6720656c69742e20517569737175"
            "652066617563696275732065782073617069656e2076697461652070656c"
            "6c656e7465737175652073656d20706c6163657261742e20496e20696420"
            "637572737573206d69207072657469756d2074656c6c7573206475697320"
            "636f6e76616c6c69732e2054656d707573206c656f2065752061656e6561"
            "6e20736564206469616d2075726e612074656d706f722e2050756c76696e"
            "617220766976616d7573206672696e67696c6c61206c61637573206e6563"
            "206d6574757320626962656e64756d20656765737461732e20496163756c"
            "6973206d61737361206e69736c206d616c657375616461206c6163696e69"
            "6120696e7465676572206e756e6320706f73756572652e2055742068656e"
            "6472657269742073656d7065722076656c20636c61737320617074656e74"
            "2074616369746920736f63696f7371752e204164206c69746f726120746f"
            "727175656e742070657220636f6e75626961206e6f7374726120696e6365"
            "70746f732068696d656e61656f732e0a0a4c6f72656d20697073756d2064"
            "200000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000020d8060c746f"
            "732068696d656e61656f732e0a11000000000000",
            "73d3dd96ca2e2f0144a117019256d770ee7c6febeaee09b24956c723ae22b529",
            id="large",
        ),
    ],
)


@pytest.mark.parametrize(*PARAMS)
def test_lzop_decompress(data: str, digest: str) -> None:
    assert hashlib.sha256(lzop.decompress(bytes.fromhex(data))).hexdigest() == digest


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        # lzop -F, without checksums
        pytest.param(
            "894c5a4f000d0a1a0a104020a0094001050300000c000000006b061af5000000000029b502ef00000044000000290e4b75736a65"
            "732c2076616e20535254210a200340000c736a65732c2076616e20535254210a11000000000000",
            b"Kusjes, van SRT!\n" * 4,
            id="none",
        ),
        # lzop -CC, with Adler-32 checksums of the data and of the compressed data
        pytest.param(
            "894c5a4f000d0a1a0a104020a0094001050300000f000000006b061af5000000000029df02f20000004400000029f24e1529f211"
            "0a630e4b75736a65732c2076616e20535254210a200340000c736a65732c2076616e20535254210a11000000000000",
            b"Kusjes, van SRT!\n" * 4,
            id="adler32",
        ),
        # lzop --crc32 -CC, with CRC-32 checksums of the header, the data and the compressed data
        pytest.param(
            "894c5a4f000d0a1a0a104020a0100101050300130c000000006b061af50000000000fdd0a69e00000044000000290cb3030aea41"
            "99020e4b75736a65732c2076616e20535254210a200340000c736a65732c2076616e20535254210a11000000000000",
            b"Kusjes, van SRT!\n" * 4,
            id="crc32",
        ),
        # lzop -CC of data that doesn't get smaller, a stored block has no checksum of compressed data
        pytest.param(
            "894c5a4f000d0a1a0a104020a0094001050300000f000000006b061af5000000000029df02f20000002000000020301811e05fec"
            "eb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e900000000",
            hashlib.sha256(b"0").digest(),
            id="stored",
        ),
    ],
)
def test_lzop_decompress_checksums(data: str, expected: bytes) -> None:
    """Test whether the checksums that the flags in the header enable are skipped."""
    assert lzop.decompress(bytes.fromhex(data)) == expected


COMPRESS_PARAMS = (
    ("data",),
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"Kusjes, van SRT!\n", id="literal"),
        pytest.param(bytes(range(256)) * 128, id="repeated"),
        # Blocks are at most 256 KiB, the last block is smaller
        pytest.param(bytes(range(256)) * 1100, id="blocks"),
        # Blocks that don't get smaller when compressed are stored uncompressed
        pytest.param(
            b"".join(hashlib.sha256(str(i).encode()).digest() for i in range(300)),
            id="incompressible",
        ),
    ],
)


@pytest.mark.parametrize(*COMPRESS_PARAMS)
def test_lzop_compress(data: bytes) -> None:
    """Test whether compressing and decompressing data results in the original data."""
    assert lzop.decompress(lzop.compress(data)) == data
    assert lzop.decompress(lzop.compress(io.BytesIO(data))) == data


def test_lzop_compress_header() -> None:
    """Test whether the header is the one that lzop writes, for a file without a name or modification time."""
    assert lzop.compress(b"") == bytes.fromhex(
        "894c5a4f000d0a1a0a104020a00940010503000001000081a40000000000000000002aa7028900000000"
    )


def test_lzop_compress_stored() -> None:
    """Test whether a block that doesn't get smaller is stored, lzop doesn't read compressed blocks larger than that."""
    data = b"".join(hashlib.sha256(str(i).encode()).digest() for i in range(300))
    assert len(lzop.compress(data)) == len(lzop.compress(b"")) + 12 + len(data)


def test_lzop_compress_reduces_size() -> None:
    """Test whether compressing data that has a lot of matches results in a smaller stream."""
    data = bytes(range(256)) * 128
    assert len(lzop.compress(data)) < len(data)


@pytest.mark.benchmark
@pytest.mark.parametrize(*PARAMS)
def test_benchmark_lzop_decompress(data: str, digest: str, benchmark: BenchmarkFixture) -> None:
    assert hashlib.sha256(benchmark(lzop.decompress, bytes.fromhex(data))).hexdigest() == digest


@pytest.mark.benchmark
def test_benchmark_lzop_compress(benchmark: BenchmarkFixture) -> None:
    # The blocks are compressed with the native LZO implementation if it's available, which compresses differently
    data = bytes(range(256)) * 128
    assert lzop.decompress(benchmark(lzop.compress, data)) == data
