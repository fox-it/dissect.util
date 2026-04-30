from __future__ import annotations

from dissect.util.blockbitmap import bitmap_to_runs


def test_bitmap_parse() -> None:
    bitmap = (b"\xff" * 136) + b"\x07" + (b"\x00" * 63) + b"\x08" + (b"\x00" * 54) + b"\x80" + (b"\xff" * 768)

    unallocated, allocated = bitmap_to_runs(bitmap, 1, 2047)

    assert allocated == [(1, 1091), (1604, 1)]
    assert unallocated == [(1092, 512), (1605, 443)]

    bitmap = b"\xff" * 203 + b"\x1f\x00\x00\x00\x00\xfe" + b"\xff" * 15

    unallocated, allocated = bitmap_to_runs(bitmap, 0, 1790)

    assert unallocated == [(1629, 36)]
    assert allocated == [(0, 1629), (1665, 125)]
