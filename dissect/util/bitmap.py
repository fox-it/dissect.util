from __future__ import annotations

from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from collections.abc import Iterator


def is_bit_set(bitmap: bytes, index: int, *, size: int = -1) -> bool:
    """Check if a bit is set in a bitmap.

    Args:
        bitmap: The bitmap to check.
        index: The index of the bit to check.

    Returns:
        True if the bit is set, False otherwise.
    """
    if size != -1 and index >= size:
        raise IndexError("Bit index out of range")

    byte_idx, bit_idx = divmod(index, 8)
    if byte_idx >= len(bitmap):
        raise IndexError("Bit index out of range")
    return (bitmap[byte_idx] & (1 << bit_idx)) != 0


def is_bit_unset(bitmap: bytes, index: int, *, size: int = -1) -> bool:
    """Check if a bit is unset in a bitmap.

    Args:
        bitmap: The bitmap to check.
        index: The index of the bit to check.

    Returns:
        True if the bit is unset, False otherwise.
    """
    return not is_bit_set(bitmap, index, size=size)


def iter_bits(bitmap: bytes, size: int = -1, start: int = 0, count: int = -1) -> Iterator[int]:
    """Iterate a bitmap, yielding individual bits as integers (0 or 1).

    Optionally specify a ``size`` in bits to ignore trailing padding bits, a ``start`` bit to start from and
    a ``count`` of bits to parse.

    Args:
        bitmap: The bitmap to parse.
        size: The actual size in bits of the bitmap. If given as ``-1`` or not provided, the entire bitmap will be used.
        start: Bit to start from.
        count: Number of bits to parse. If given as ``-1`` or not provided, all bits after the start bit will be parsed.

    Yields:
        Individual bits as integers (0 or 1).
    """
    bit_int = int.from_bytes(bitmap, "little")
    if size == -1:
        size = len(bitmap) * 8

    if count == -1:
        count = size - start

    # I hate that this is faster
    bit_str = f"{bit_int:0>{size}b}"[-start - 1 : -start - count - 1 : -1]
    yield from map(int, bit_str)


def iter_bit_runs(bitmap: bytes, size: int = -1, start: int = 0, count: int = -1) -> Iterator[tuple[int, int]]:
    """Iterate a bitmap, yielding tuples of ``(bit_value, bit_count)``.

    Optionally specify a ``size`` in bits to ignore trailing padding bits, a ``start`` bit to start from and
    a ``count`` of bits to parse.

    Args:
        bitmap: The bitmap to parse.
        size: The actual size in bits of the bitmap. If given as ``-1`` or not provided, the entire bitmap will be used.
        start: Bit to start from.
        count: Number of bits to parse. If given as ``-1`` or not provided, all bits after the start bit will be parsed.

    Yields:
        Tuples of ``(bit_value, bit_count)``.
    """
    if size == -1:
        size = len(bitmap) * 8

    if count == -1:
        count = size - start

    byte_idx, bit_idx = divmod(start, 8)
    remaining_bits = min(size - start, count)

    current_bit = (bitmap[byte_idx] & (1 << bit_idx)) >> bit_idx
    current_count = 0

    for byte in bitmap[byte_idx:]:
        if remaining_bits == 0:
            break

        if byte in (0x00, 0xFF):
            max_count = min(remaining_bits, 8 - bit_idx)

            if (current_bit == 0 and byte == 0xFF) or (current_bit == 1 and byte == 0x00):
                yield (current_bit, current_count)
                current_bit = 1 - current_bit
                current_count = max_count
            else:
                current_count += max_count

            remaining_bits -= max_count
        else:
            for cur_bit_idx in range(bit_idx, min(remaining_bits, 8)):
                bit_value = (byte & (1 << cur_bit_idx)) >> cur_bit_idx

                if bit_value == current_bit:
                    current_count += 1
                else:
                    yield (current_bit, current_count)
                    current_bit = bit_value
                    current_count = 1

                remaining_bits -= 1

        bit_idx = 0

    if current_count:
        yield (current_bit, current_count)


T = TypeVar("T")


def squash_and_split_bitmap_runs(
    runs: Iterator[tuple[T, int]], offset: int = 0
) -> tuple[list[tuple[T, int]], list[tuple[T, int]]]:
    """Split a given bitmap runlist into two runlists, one for unset bits and one for set bits.

    Sequential runs of the same type will be merged into a single run of (offset, length).
    The offset of each run will be adjusted by the given offset value.

    Note that the input runs are expected to be in the format of ``(bit_value, bit_count)``, where ``bit_value`` can be
    any type that can be evaluated as ``True`` or ``False``.

    Args:
        runs: An iterator of tuples, where every tuple is in the format ``(bit_value, bit_count)``.
        offset: Optional value to add to every run offset.

    Returns:
        A tuple of two runlists: The first being for unset bits and the second for set bits.
    """
    runlist_unset_bits = []
    runlist_set_bits = []
    current_run_is_set = None

    current_run_length = 0
    current_run_offset = 0
    for run_is_set, run_length in runs:
        if current_run_is_set != run_is_set and current_run_length > 0:
            # Switch from bit value: finish previous run
            runlist = runlist_set_bits if current_run_is_set else runlist_unset_bits
            runlist.append((offset + current_run_offset, current_run_length))

            current_run_offset += current_run_length
            current_run_length = 0

        current_run_is_set = run_is_set
        current_run_length += run_length

    # Flush last run
    if current_run_length > 0:
        runlist = runlist_set_bits if current_run_is_set else runlist_unset_bits
        runlist.append((offset + current_run_offset, current_run_length))

    return runlist_unset_bits, runlist_set_bits


def bitmap_to_runlists(
    bitmap: bytes, offset: int = 0, count: int = -1
) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
    """Convert a bitmap into two lists of runlists, one for unset bits and one for set bits.

    A runlist is a list of tuples, where each tuple contains an offset and a length.

    Args:
        bitmap: The bitmap to parse.
        offset: Optional base value to offset the runlists with.
        count: Optional number of bits to consider from the bitmap. Defaults to -1, which means all bits.

    Returns:
        A tuple of two runlists: The first being for unset bits and the second for set bits.
    """
    if count is None:
        count = len(bitmap) * 8

    runs = iter_bit_runs(bitmap, size=count)
    return squash_and_split_bitmap_runs(runs, offset)
