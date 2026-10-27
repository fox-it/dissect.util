from __future__ import annotations

import io
import struct
import sys

import pytest

from dissect.util.xmemoryview import _xmemoryview, xmemoryview

# The non-native endianness, which results in an _xmemoryview instead of a regular memoryview
NON_NATIVE = ">" if sys.byteorder == "little" else "<"


def test_xmemoryview_little() -> None:
    # This is mostly a sanity test, since this will be a native memoryview on little endian systems
    buf = bytearray(range(256))
    view = memoryview(buf).cast("I")

    xview = xmemoryview(buf, "<I")
    assert xview.format == "I"
    assert xview.ndim == 1
    assert len(xview) == len(view)
    assert xview[0] == 0x03020100
    assert xview[:4].tobytes() == b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    assert xview[0:5].tolist() == [0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C, 0x13121110]

    xview[0] = 0x12345678
    assert xview[0] == 0x12345678
    assert buf[:4] == b"\x78\x56\x34\x12"
    xview[0] = 0x03020100
    # Setting a slice is not actually supported by memoryview, so don't test it

    it = iter(xview)
    assert list(it)[:5] == [0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C, 0x13121110]


def test_xmemoryview_big() -> None:
    buf = bytearray(range(256))
    view = memoryview(buf).cast("I")

    xview = xmemoryview(buf, ">I")
    assert xview.format == "I"
    assert xview.ndim == 1
    assert len(xview) == len(view)
    assert xview[0] == 0x00010203
    assert xview[:4].tobytes() == b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    assert xview[0:5].tolist() == [0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F, 0x10111213]
    assert xview[0:10] == xview[0:10]

    xview[0] = 0x12345678
    assert xview[0] == 0x12345678
    assert buf[:4] == b"\x12\x34\x56\x78"
    xview[0] = 0x00010203
    # Setting a slice is not actually supported by memoryview, so don't test it

    it = iter(xview)
    assert list(it)[:5] == [0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F, 0x10111213]


def test_xmemoryview_bytes() -> None:
    buf = bytearray(range(16))
    xview = xmemoryview(buf, f"{NON_NATIVE}I")
    assert isinstance(xview, _xmemoryview)

    assert bytes(xview) == bytes(buf)
    assert bytes(xview[1:3]) == bytes(buf[4:12])
    assert bytes(xview[::2]) == bytes(buf[0:4] + buf[8:12])


@pytest.mark.skipif(sys.version_info < (3, 12), reason="the buffer protocol for Python classes requires Python 3.12+")
def test_xmemoryview_buffer() -> None:
    buf = bytearray(range(16))
    xview = xmemoryview(buf, f"{NON_NATIVE}I")
    assert isinstance(xview, _xmemoryview)

    view = memoryview(xview)
    assert view.format == "B"
    assert view.nbytes == len(buf)
    assert view.tobytes() == bytes(buf)

    assert io.BytesIO(xview).read() == bytes(buf)
    assert struct.unpack_from(f"{NON_NATIVE}I", xview) == (xview[0],)
    assert bytes(xview[::2]) == bytes(buf[0:4] + buf[8:12])

    # Writes through the buffer are reflected in the underlying buffer
    view[0] = 0xFF
    assert buf[0] == 0xFF
