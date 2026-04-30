from __future__ import annotations


def bitmap_to_runs(
    bitmap: bytes, initial_block_offset: int, max_num_blocks: int
) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
    """Convert a bitmap (bitfield) into two lists of block runs: unallocated and allocated.

    Each byte in a block `bitmap` represents 8 blocks (bits). A set bit means allocated, unset means unallocated.

    Returns:
        - unallocated: list of (start_offset, length) tuples for contiguous unallocated runs
        - allocated:   list of (start_offset, length) tuples for contiguous allocated runs

    Only up to `max_num_blocks` blocks are considered, starting at `initial_block_offset`.
    """
    runs = []

    # Consider each byte as a set of 'runs' depending on whether the individual bits are set
    for byte in bitmap:
        if byte == 255:
            # All 8 blocks are allocated
            runs.append((8, True))
        elif byte == 0:
            # All 8 blocks are unallocated
            runs.append((8, False))
        else:
            previous_bit_is_allocated = None
            bit_run_length = 0
            for bit_idx in range(8):
                bit_is_allocated = bool((byte >> bit_idx) & 1)
                if previous_bit_is_allocated != bit_is_allocated and previous_bit_is_allocated is not None:
                    # Finish previous bit run
                    runs.append((bit_run_length, previous_bit_is_allocated))
                    bit_run_length = 0

                previous_bit_is_allocated = bit_is_allocated
                bit_run_length += 1
            # Flush last bit run
            if bit_run_length > 0:
                runs.append((bit_run_length, previous_bit_is_allocated))

    # Squash sequential runs of the same allocation into one run and convert into one runlist for allocated and
    # unallocated
    unallocated = []
    allocated = []
    current_run_is_allocated = None

    current_run_length = 0
    current_run_offset = 0
    for run_length, run_is_allocated in runs:
        if current_run_is_allocated != run_is_allocated and current_run_is_allocated is not None:
            # Finish previous run
            blocks_to_append = min(current_run_length, max_num_blocks - current_run_offset)
            runlist = allocated if current_run_is_allocated else unallocated
            if blocks_to_append > 0:
                runlist.append((initial_block_offset + current_run_offset, blocks_to_append))

            current_run_offset += blocks_to_append
            current_run_length = 0

        current_run_is_allocated = run_is_allocated
        current_run_length += run_length

    # Flush last run
    blocks_to_append = min(current_run_length, max_num_blocks - current_run_offset)
    runlist = allocated if current_run_is_allocated else unallocated

    if blocks_to_append > 0:
        runlist.append((initial_block_offset + current_run_offset, blocks_to_append))

    return unallocated, allocated
