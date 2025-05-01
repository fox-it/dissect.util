from __future__ import annotations

from dissect.util.xmemoryview import xmemoryview


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

    it = iter(xview)
    assert list(it)[:5] == [0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F, 0x10111213]
