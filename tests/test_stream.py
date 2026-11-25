from __future__ import annotations

import io
import zlib
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.util import stream

if TYPE_CHECKING:
    from collections.abc import Iterator

    from pytest_benchmark.fixture import BenchmarkFixture


def test_range_stream() -> None:
    buf = io.BytesIO(b"\x01" * 10 + b"\x02" * 10 + b"\x03" * 10)
    fh = stream.RangeStream(buf, 5, 15)

    assert fh.read(10) == b"\x01" * 5 + b"\x02" * 5
    assert fh.read(10) == b"\x02" * 5
    assert fh.read() == b""

    fh.seek(0)
    assert len(fh.read()) == 15
    fh.seek(0)
    assert len(fh.readall()) == 15

    fh.seek(3, io.SEEK_SET)
    assert fh.tell() == 3
    assert fh.read(10) == b"\x01" * 2 + b"\x02" * 8

    fh.seek(-8, io.SEEK_CUR)
    assert fh.tell() == 5
    assert fh.read(10) == b"\x02" * 10

    fh.seek(-5, io.SEEK_END)
    assert fh.read(5) == b"\x02" * 5

    fh.seek(20, io.SEEK_SET)
    assert fh.read(10) == b""

    fh.seek(-50, io.SEEK_CUR)
    assert fh.tell() == 0

    fh.seek(-50, io.SEEK_END)
    assert fh.tell() == 0


def test_relative_stream() -> None:
    buf = io.BytesIO(b"\x01" * 10 + b"\x02" * 10 + b"\x03" * 10)
    fh = stream.RelativeStream(buf, 5)

    assert fh.read(10) == b"\x01" * 5 + b"\x02" * 5

    fh.seek(3, io.SEEK_SET)
    assert fh.tell() == 3
    assert fh.read(10) == b"\x01" * 2 + b"\x02" * 8

    fh.seek(-8, io.SEEK_CUR)
    assert fh.tell() == 5
    assert fh.read(10) == b"\x02" * 10

    fh.seek(-15, io.SEEK_END)
    assert fh.tell() == 10
    assert fh.read(15) == b"\x02" * 5 + b"\x03" * 10
    assert fh.read(1) == b""

    fh.seek(0)
    fh._buf = None
    assert fh.read() == b"\x01" * 5 + b"\x02" * 10 + b"\x03" * 10


def test_buffered_stream() -> None:
    buf = io.BytesIO(b"\x01" * 512 + b"\x02" * 512 + b"\x03" * 512)
    fh = stream.BufferedStream(buf, size=None)

    assert fh.read(10) == b"\x01" * 10
    assert fh._buf == buf.getvalue()
    assert fh.read() == buf.getvalue()[10:]
    assert fh.read(1) == b""


def test_mapping_stream() -> None:
    buffers = [
        io.BytesIO(b"\x01" * 512),
        io.BytesIO(b"\x02" * 512),
        io.BytesIO(b"\x03" * 512),
        io.BytesIO(b"\x04" * 512),
    ]
    fh = stream.MappingStream()
    # Add them in different orders to test if sorting works
    fh.add(0, 512, buffers[0])
    fh.add(1536, 512, buffers[3])
    fh.add(1024, 512, buffers[2])
    fh.add(512, 512, buffers[1])

    assert fh.read() == (b"\x01" * 512) + (b"\x02" * 512) + (b"\x03" * 512) + (b"\x04" * 512)

    fh.add(2048, 412, io.BytesIO(b"\x05" * 512), 100)
    assert fh.read(512) == b"\x05" * 412
    assert fh.read(1) == b""


def test_mapping_stream_same_offset() -> None:
    buffers = [
        io.BytesIO(b"\x01" * 512),
        io.BytesIO(b"\x02" * 512),
    ]
    fh = stream.MappingStream()
    # Add them in different orders to test if sorting works
    fh.add(0, 1024, buffers[0])
    fh.add(0, 1024, buffers[1])  # This should not raise an exception in add()

    assert fh._runs[0][2] == buffers[0]
    assert fh._runs[1][2] == buffers[1]


def test_lookup_stream() -> None:
    buf = io.BytesIO(b"\x01" * 512 + b"\x02" * 512)
    lookup_calls: list[tuple[int, int]] = []

    def lookup(offset: int, length: int) -> Iterator[tuple[int | None, int]]:
        lookup_calls.append((offset, length))
        if offset < 512:
            size = min(512 - offset, length)
            yield (0, size)
            offset += size
            length -= size
        if length > 0:
            yield (512, length)

    fh = stream.LookupStream(buf, 1024, lookup=lookup, align=256)

    assert fh.read(256) == b"\x01" * 256
    assert lookup_calls == [(0, 256)]

    assert fh.read(256) == b"\x01" * 256
    assert lookup_calls == [(0, 256), (256, 256)]

    fh.seek(512)
    assert fh.read(256) == b"\x02" * 256
    assert lookup_calls == [(0, 256), (256, 256), (512, 256)]

    sparse = stream.LookupStream(io.BytesIO(b""), 16, lookup=lambda offset, length: iter([(None, length)]))
    assert sparse.read() == b"\x00" * 16


def test_lookup_stream_exhausted() -> None:
    buf = io.BytesIO(b"\x01" * 16)

    def partial(offset: int, length: int) -> Iterator[tuple[int | None, int]]:
        # Only the first 8 bytes are mapped
        if offset < 8:
            yield (offset, min(8 - offset, length))

    empty = stream.LookupStream(buf, 16, lookup=lambda offset, length: iter([]))
    assert empty.read(16) == b""

    truncated = stream.LookupStream(buf, 16, lookup=partial)
    assert truncated.read(16) == b"\x01" * 8


def test_lookup_stream_not_implemented() -> None:
    fh = stream.LookupStream(io.BytesIO(b"\x01" * 16), 16)

    with pytest.raises(NotImplementedError):
        fh.read(16)


def test_runlist_stream() -> None:
    buf = io.BytesIO(b"\x01" * 512 + b"\x02" * 512 + b"\x03" * 512)
    fh = stream.RunlistStream(buf, [(0, 32), (32, 16), (48, 48)], 1536, 16)

    assert fh.read(32) == b"\x01" * 32
    assert fh.read(512) == b"\x01" * 480 + b"\x02" * 32

    fh.seek(-768, io.SEEK_END)
    assert fh.read(768) == b"\x02" * 256 + b"\x03" * 512

    fh.runlist += [(0, 32)]
    fh.size += 32 * 16
    assert fh.read(512) == b"\x01" * 512
    assert fh.read(1) == b""


def test_aligned_stream_buffer() -> None:
    buf = io.BytesIO(b"\x01" * 512 + b"\x02" * 512 + b"\x03" * 512 + b"\x04" * 512)
    fh = stream.RelativeStream(buf, 0, align=512)

    # Fill buffer
    fh.read(256)
    assert fh._buf == b"\x01" * 512
    # Reset to aligned offset from where the buffer was read
    fh.seek(0)
    # Read aligned blocks so we move past the offset from where the buffer was read
    fh.read(1024)
    # Buffer should be reset
    assert fh._buf is None
    # Buffer should now be from the 3rd aligned block
    assert fh.read(256) == b"\x03" * 256
    assert fh._buf == b"\x03" * 512


def test_overlay_stream() -> None:
    buf = io.BytesIO(b"\x00" * 512 * 8)
    fh = stream.OverlayStream(buf, size=512 * 8, align=512)

    # Sanity check
    assert fh.read() == b"\x00" * 512 * 8
    fh.seek(0)

    # Add a small overlay
    fh.add(512, b"\xff" * 4)

    assert fh.read(512) == b"\x00" * 512
    assert fh.read(512) == (b"\xff" * 4) + (b"\x00" * 508)

    fh.seek(510)
    assert fh.read(4) == b"\x00\x00\xff\xff"

    # Add a large unaligned overlay
    fh.add(1000, b"\x01" * 1024)

    fh.seek(1000)
    assert fh.read(1024) == b"\x01" * 1024
    fh.seek(1024)
    assert fh.read(512) == b"\x01" * 512
    fh.seek(2000)
    assert fh.read(512) == (b"\x01" * 24) + (b"\x00" * 488)

    fh.seek(2048)
    assert fh.read(512) == b"\x00" * 512

    # Add a consecutive overlay
    fh.add(516, b"\x02" * 10)

    fh.seek(510)
    assert fh.read(32) == b"\x00\x00" + (b"\xff" * 4) + (b"\x02" * 10) + (b"\x00" * 16)

    with pytest.raises(ValueError, match="Overlap with existing overlay: \\(\\(512, 4\\)\\)"):
        fh.add(500, b"\x03" * 100)

    fh.add((512 * 8) - 4, b"\x04" * 100)
    fh.seek((512 * 8) - 4)
    assert fh.read(100) == b"\x04" * 4


def test_overlay_stream_add_at_offset_zero() -> None:
    buf = io.BytesIO(b"\x00" * 100)
    fh = stream.OverlayStream(buf, size=100)

    # Add a small overlay at offset zero
    fh.add(0, b"MZ")

    assert fh.read(2) == b"MZ"

    fh.seek(0)
    assert fh.read(100) == b"MZ" + (b"\x00" * 98)

    fh.seek(0)
    assert fh.read() == b"MZ" + (b"\x00" * 98)


def test_zlib_stream() -> None:
    data = b"\x01" * 8192 + b"\x02" * 8192 + b"\x03" * 8192 + b"\x04" * 8192
    fh = stream.ZlibStream(io.BytesIO(zlib.compress(data)), size=8192 * 4, align=512)

    assert fh.read(8192) == b"\x01" * 8192
    assert fh.read(8192) == b"\x02" * 8192
    assert fh.read(8192) == b"\x03" * 8192
    assert fh.read(8192) == b"\x04" * 8192
    assert fh.read(1) == b""

    fh.seek(0)
    assert fh.read(8192) == b"\x01" * 8192

    fh.seek(1024)
    assert fh.read(8192) == b"\x01" * 7168 + b"\x02" * 1024

    fh.seek(512)
    assert fh.read(1024) == b"\x01" * 1024

    fh.seek(0)
    assert fh.readall() == data

    fh.seek(512)
    assert fh.read(1024) == b"\x01" * 1024
    with patch("io.DEFAULT_BUFFER_SIZE", 8):
        assert fh.read(1024) == b"\x01" * 1024

    fh.seek(0)
    assert fh.read() == data


def test_bitstream() -> None:
    """Test for correct bit reading behavior."""
    data = bytes([0b10101010, 0b11001100, 0b11110000, 0b00001111, 0b11111111, 0b00000000, 0b10101010, 0b01010101])
    fh = io.BytesIO(data)
    bitstream = stream.BitStream(fh)

    assert bitstream.peek(4) == 0b1010
    assert bitstream.tell() == 0

    assert bitstream.peek(4) == 0b1010
    assert bitstream.tell() == 0

    assert bitstream.read(4) == 0b1010
    assert bitstream.tell() == 4

    assert bitstream.peek(8) == 0b10101100
    assert bitstream.tell() == 4

    assert bitstream.read(4) == 0b1010
    assert bitstream.tell() == 8

    assert bitstream.peek(8) == 0b11001100
    assert bitstream.tell() == 8

    assert bitstream.read(8) == 0b11001100
    assert bitstream.tell() == 16

    assert bitstream.peek(4) == 0b1111
    assert bitstream.tell() == 16

    bitstream.remove(4)
    assert bitstream.tell() == 20

    assert bitstream.peek(4) == 0b0000
    assert bitstream.tell() == 20

    assert bitstream.read(8) == 0b00000000
    assert bitstream.tell() == 28

    assert bitstream.read(33) == 0b11111111_11110000_00001010_10100101_0
    assert bitstream.tell() == 61

    assert bitstream.seek(0) == 0
    assert bitstream.peek(16) == 0b10101010_11001100

    assert bitstream.seek(4, io.SEEK_CUR) == 4
    assert bitstream.peek(8) == 0b10101100

    assert bitstream.seek(-8, io.SEEK_END) == 56
    assert bitstream.peek(8) == 0b01010101

    fh = io.BytesIO(b"\x00\xe0")
    bitstream = stream.BitStream(fh)
    assert bitstream.read(16) == 0x00E0


def test_bitstream_empty() -> None:
    """Test reading from an empty bit stream."""
    fh = io.BytesIO(b"")
    bitstream = stream.BitStream(fh)

    assert bitstream.peek(8) == 0
    assert bitstream.read(8) == 0


def test_bitstream_eof() -> None:
    """Test reading past the end of a bit stream."""
    fh = io.BytesIO(b"\xab")
    bitstream = stream.BitStream(fh)

    assert bitstream.read(4) == 0xA
    assert bitstream.peek(8) == 0xB0
    assert bitstream.read(8) == 0xB0
    assert bitstream.tell() == 8


@pytest.mark.parametrize(
    ("byteorder", "expected", "expected_partial"),
    [
        ("big", 0b10101010_11001100_11110000_00001111, 0b11111111_00000000),
        ("little", 0b11001100_10101010_00001111_11110000, 0b00000000_11111111),
    ],
)
def test_bitstream_word_size(byteorder: str, expected: int, expected_partial: int) -> None:
    """Test reading bits from 16-bit words."""
    fh = io.BytesIO(bytes([0b10101010, 0b11001100, 0b11110000, 0b00001111, 0b11111111]))
    bitstream = stream.BitStream(fh, word_size=2, byteorder=byteorder)

    assert bitstream.peek(32) == expected
    assert bitstream.read(4) == expected >> 28
    assert bitstream.tell() == 4

    # Words are always read whole
    assert bitstream.seek(20) == 20
    assert bitstream.bits == 12
    assert bitstream.read(12) == expected & 0xFFF

    # A partial word at the end of the stream is padded with zero bytes
    assert bitstream.read(16) == expected_partial
    assert bitstream.tell() == 48


def test_bitstream_read_bytes() -> None:
    """Test reading bytes interleaved with the bit stream."""
    fh = io.BytesIO(b"\x12\x34\x56\x78\x9a\xbc")
    bitstream = stream.BitStream(fh, word_size=2, byteorder="little")

    assert bitstream.read(4) == 0x3
    assert bitstream.read_bytes(1) == b"\x56"
    assert bitstream.read(12) == 0x412
    assert bitstream.read(16) == 0x9A78
    assert bitstream.read_bytes(2) == b"\xbc"


class NullStream(stream.AlignedStream):
    def __init__(self, size: int | None, align: int = stream.STREAM_BUFFER_SIZE):
        super().__init__(size)

    def _read(self, offset: int, length: int) -> bytes:
        return b"\x00" * length


@pytest.mark.benchmark
def test_aligned_stream_read_fixed_size_benchmark(benchmark: BenchmarkFixture) -> None:
    fh = NullStream(1024 * 1024)

    @benchmark
    def run() -> None:
        fh.seek(0)
        fh.read(1234)

    assert run is None


@pytest.mark.benchmark
def test_aligned_stream_read_none_size_benchmark(benchmark: BenchmarkFixture) -> None:
    fh = NullStream(None)

    @benchmark
    def run() -> None:
        fh.seek(0)
        fh.read(1234)

    assert run is None
