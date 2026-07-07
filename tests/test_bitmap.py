from __future__ import annotations

from dissect.util.bitmap import bitmap_to_runlists, is_bit_set, is_bit_unset, iter_bit_runs, iter_bits


def test_is_bit_set_and_unset() -> None:
    """Test that we can correctly check if bits are set or unset in a bitmap."""
    bitmap = b"\x01\x02\x04\x08\x10\x20\x40\x80"

    assert is_bit_set(bitmap, 0)
    assert not is_bit_unset(bitmap, 0)
    assert is_bit_set(bitmap, 9)
    assert not is_bit_unset(bitmap, 9)
    assert is_bit_set(bitmap, 18)
    assert not is_bit_unset(bitmap, 18)
    assert is_bit_set(bitmap, 27)
    assert not is_bit_unset(bitmap, 27)
    assert is_bit_set(bitmap, 36)
    assert not is_bit_unset(bitmap, 36)
    assert is_bit_set(bitmap, 45)
    assert not is_bit_unset(bitmap, 45)
    assert is_bit_set(bitmap, 54)
    assert not is_bit_unset(bitmap, 54)
    assert is_bit_set(bitmap, 63)
    assert not is_bit_unset(bitmap, 63)

    assert is_bit_unset(bitmap, 1)
    assert not is_bit_set(bitmap, 1)
    assert is_bit_unset(bitmap, 8)
    assert not is_bit_set(bitmap, 8)
    assert is_bit_unset(bitmap, 17)
    assert not is_bit_set(bitmap, 17)
    assert is_bit_unset(bitmap, 26)
    assert not is_bit_set(bitmap, 26)
    assert is_bit_unset(bitmap, 35)
    assert not is_bit_set(bitmap, 35)
    assert is_bit_unset(bitmap, 44)
    assert not is_bit_set(bitmap, 44)
    assert is_bit_unset(bitmap, 53)
    assert not is_bit_set(bitmap, 53)
    assert is_bit_unset(bitmap, 62)
    assert not is_bit_set(bitmap, 62)


def test_iter_bits() -> None:
    """Test that we can correctly iterate bits in a bitmap."""
    bitmap = b"\x01\x02\x04\x08\x10\x20\x40\x80\x00"

    # fmt: off
    assert list(iter_bits(bitmap)) == [
        1, 0, 0, 0, 0, 0, 0, 0,
        0, 1, 0, 0, 0, 0, 0, 0,
        0, 0, 1, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 0, 0, 0, 0,
        0, 0, 0, 0, 1, 0, 0, 0,
        0, 0, 0, 0, 0, 1, 0, 0,
        0, 0, 0, 0, 0, 0, 1, 0,
        0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 0, 0, 0, 0, 0
    ]

    assert list(iter_bits(bitmap, size=60)) == [
        1, 0, 0, 0, 0, 0, 0, 0,
        0, 1, 0, 0, 0, 0, 0, 0,
        0, 0, 1, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 0, 0, 0, 0,
        0, 0, 0, 0, 1, 0, 0, 0,
        0, 0, 0, 0, 0, 1, 0, 0,
        0, 0, 0, 0, 0, 0, 1, 0,
        0, 0, 0, 0
    ]

    assert list(iter_bits(bitmap, start=4, count=16)) == [
        0, 0, 0, 0, 0, 1, 0, 0,
        0, 0, 0, 0, 0, 0, 1, 0,
    ]

    assert list(iter_bits(bitmap, size=16, start=9, count=1)) == [1]
    # fmt: on


def test_iter_bit_runs() -> None:
    """Test that we can correctly iterate bit runs in a bitmap."""
    bitmap = b"\x0f\xff\x00\x07\x00"

    # fmt: off
    assert list(iter_bit_runs(bitmap)) == [
        (1, 4),
        (0, 4),
        (1, 8),
        (0, 8),
        (1, 3),
        (0, 13)
    ]

    assert list(iter_bit_runs(bitmap, size=32)) == [
        (1, 4),
        (0, 4),
        (1, 8),
        (0, 8),
        (1, 3),
        (0, 5)
    ]

    assert list(iter_bit_runs(bitmap, start=4, count=16)) == [
        (0, 4),
        (1, 8),
        (0, 4)
    ]

    assert list(iter_bit_runs(bitmap, size=16, start=9, count=9)) == [
        (1, 7),
    ]

    assert list(iter_bit_runs(bitmap, size=16, start=9, count=1)) == [
        (1, 1)
    ]
    # fmt: on


def test_bitmap_to_runlists() -> None:
    """Test that we can correctly convert a bitmap to runlists of set and unset bits."""
    bitmap = (b"\xff" * 136) + b"\x07" + (b"\x00" * 63) + b"\x08" + (b"\x00" * 54) + b"\x80" + (b"\xff" * 768)

    unallocated, allocated = bitmap_to_runlists(bitmap, 1, 2047)

    assert allocated == [(1, 1091), (1604, 1)]
    assert unallocated == [(1092, 512), (1605, 443)]

    bitmap = b"\xff" * 203 + b"\x1f\x00\x00\x00\x00\xfe" + b"\xff" * 15

    unallocated, allocated = bitmap_to_runlists(bitmap, 0, 1790)

    assert unallocated == [(1629, 36)]
    assert allocated == [(0, 1629), (1665, 125)]
