from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator


def squash_and_split_bitmap_runs(
    runs: Iterator[tuple[int, bool]], offset: int = 0
) -> tuple[list[tuple[int, bool]], list[tuple[int, bool]]]:
    """Given a list of 'runs' of bit counts and bit values (set / unset), split into two lists (the first being unset
    bits, the second being set bits) of 'squashed' runs where sequential runs of the same type are merged into a single
    run of (offset, length).

    Note that the second element of the tuples will be evaluated on whether it evaluates to True or not. It therefore
    technically does not need to be a bool: ints of (non)zero are fine as well.

    Args:
        runs: An iterator of tuples, where every tuple is in the format (bit_count, bit_value).
        offset: Optional value to add to every run offset.

    Returns:
        A tuple of two squashed (and optionally offset added) bitmap runs, the first being for unset bits and the second
        for set bits.
    """
    bits_unset_runlist = []
    bits_set_runlist = []
    current_run_is_set = None

    current_run_length = 0
    current_run_offset = 0
    for run_is_set, run_length in runs:
        if current_run_is_set != run_is_set and current_run_length > 0:
            # Switch from bit value: finish previous run
            runlist = bits_set_runlist if current_run_is_set else bits_unset_runlist
            runlist.append((offset + current_run_offset, current_run_length))

            current_run_offset += current_run_length
            current_run_length = 0

        current_run_is_set = run_is_set
        current_run_length += run_length

    # Flush last run
    if current_run_length > 0:
        runlist = bits_set_runlist if current_run_is_set else bits_unset_runlist
        runlist.append((offset + current_run_offset, current_run_length))

    return bits_unset_runlist, bits_set_runlist


def iter_bitmap(bitmap: bytes, bitmap_size: int, start: int, count: int) -> Iterator[tuple[int, int]]:
    """Iterate a bitmap of a given size from a given offset and count, yielding tuples of (bit_value, bit_count).

    Args:
        bitmap: The bitmap to parse.
        bitmap_size: The actual size in bits of the bitmap. Needed to ignore trailing padding bits.
        start: Bit to start from.
        count: Number of bits to parse.

    Returns:
        An iterator of tuples of (bit_value, bit_count).
    """
    byte_idx, bit_idx = divmod(start, 8)
    remaining_bits = bitmap_size - start
    current_bit = (bitmap[byte_idx] & (1 << bit_idx)) >> bit_idx
    current_count = 0

    for byte in bitmap[byte_idx:]:
        if count == 0 or remaining_bits == 0:
            break

        if (current_bit, byte) == (0, 0) or (current_bit, byte) == (1, 0xFF):
            max_count = min(count, remaining_bits, 8 - bit_idx)
            current_count += max_count
            remaining_bits -= max_count
            count -= max_count
            bit_idx = 0
        else:
            for cur_bit_idx in range(bit_idx, min(count, remaining_bits, 8)):
                bit_set = (byte & (1 << cur_bit_idx)) >> cur_bit_idx

                if bit_set == current_bit:
                    current_count += 1
                else:
                    yield (current_bit, current_count)
                    current_bit = bit_set
                    current_count = 1

                remaining_bits -= 1
                count -= 1

    if current_count:
        yield (current_bit, current_count)


def bitmap_to_runlists(
    bitmap: bytes, runlist_offset: int = 0, max_bit_count: int | None = None
) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
    """Convert a bitmap into two lists of runlists (tuples of offset and length), one for bits unset and one for bits
    set.

    Args:
        bitmap: The bitmap to parse.
        runlist_offset: Optional value to add to the returned runlist offsets.

    Returns:
        A tuple of two runlists: The first being for unset bits and the second for set bits.
    """
    if max_bit_count is None:
        max_bit_count = len(bitmap) * 8
    return squash_and_split_bitmap_runs(iter_bitmap(bitmap, max_bit_count, 0, max_bit_count), runlist_offset)
