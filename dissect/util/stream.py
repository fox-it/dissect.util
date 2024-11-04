from __future__ import annotations

import io
import os
import sys
import zlib
from bisect import bisect_left, bisect_right
from threading import Lock
from typing import BinaryIO

STREAM_BUFFER_SIZE = int(os.getenv("DISSECT_STREAM_BUFFER_SIZE", io.DEFAULT_BUFFER_SIZE))


class AlignedStream(io.RawIOBase):
    """Basic buffered stream that provides aligned reads.

    Must be subclassed for various stream implementations. Subclasses can implement:
        - :meth:`~AlignedStream._read`
        - :meth:`~AlignedStream._readinto`
        - :meth:`~AlignedStream._seek`

    The offset and length for ``_read`` and ``_readinto`` are guaranteed to be aligned. The only time
    that overriding _seek would make sense is if there's no known size of your stream,
    but still want to provide ``SEEK_END`` functionality.

    Most subclasses of ``AlignedStream`` take one or more file-like objects as source.
    Operations on these subclasses, like reading, will modify the source file-like object as a side effect.

    Args:
        size: The size of the stream. This is used in read and seek operations. ``None`` if unknown.
        align: The alignment size. Read operations are aligned on this boundary. Also determines buffer size.

    .. automethod:: _read
    .. automethod:: _readinto
    .. automethod:: _seek
    """

    def __init__(self, size: int | None = None, align: int = STREAM_BUFFER_SIZE):
        super().__init__()
        self.size = size
        self.align = align

        self._pos = 0
        self._pos_align = 0

        self._buf = memoryview(bytearray(align))
        self._buf_size = 0
        self._read_lock = Lock()

    def readable(self) -> bool:
        """Indicate that the stream is readable."""
        return True

    def seekable(self) -> bool:
        """Indicate that the stream is seekable."""
        return True

    def seek(self, pos: int, whence: int = io.SEEK_SET) -> int:
        """Seek the stream to the specified position."""
        with self._read_lock:
            pos = self._seek(pos, whence)
            self._set_pos(pos)

            return pos

    def _seek(self, pos: int, whence: int = io.SEEK_SET) -> int:
        """Calculate and return the new stream position after a seek."""
        if whence == io.SEEK_SET:
            if pos < 0:
                raise ValueError(f"negative seek position {pos}")
        elif whence == io.SEEK_CUR:
            pos = max(0, self._pos + pos)
        elif whence == io.SEEK_END:
            if self.size is None:
                raise IOError("invalid whence value for stream with no size")
            pos = max(0, self.size + pos)
        else:
            raise IOError("invalid whence value")

        return pos

    def _set_pos(self, pos: int) -> None:
        """Update the position and aligned position within the stream."""
        new_pos_align = pos - (pos % self.align)

        if self._pos_align != new_pos_align:
            self._pos_align = new_pos_align
            self._buf_size = 0

        self._pos = pos

    def tell(self) -> int:
        """Return current stream position."""
        return self._pos

    def _fill_buf(self) -> None:
        """Fill the alignment buffer if we can."""
        if self._buf_size or self.size is not None and (self.size <= self._pos or self.size <= self._pos_align):
            # Don't fill the buffer if:
            # - We already have a buffer
            # - The stream position is at the end (or beyond) the stream size
            return

        self._buf_size = self._readinto(self._pos_align, self._buf)

    def readinto(self, b: bytearray) -> int:
        """Read bytes into a pre-allocated bytes-like object b.

        Returns an int representing the number of bytes read (0 for EOF).
        """
        with self._read_lock:
            return self._readinto_unlocked(b)

    def _readinto_unlocked(self, b: bytearray) -> int:
        if not isinstance(b, memoryview):
            b = memoryview(b)
        b = b.cast("B")

        n = len(b)
        size = self.size
        align = self.align
        total_read = 0

        # If we know the stream size, adjust n
        if size is not None:
            remaining = size - self._pos

            if n == -1:
                n = remaining
            else:
                n = min(n, remaining)

        # Short path for when it turns out we don't need to read anything
        if n == 0 or size is not None and size <= self._pos:
            return 0

        # Read misaligned start from buffer
        if self._pos != self._pos_align:
            self._fill_buf()

            buffer_pos = self._pos - self._pos_align
            buffer_remaining = max(0, min(align, self._buf_size) - buffer_pos)
            read_len = min(n, buffer_remaining)

            b[:read_len] = self._buf[buffer_pos : buffer_pos + read_len]
            b = b[read_len:]

            n -= read_len
            total_read += read_len
            self._set_pos(self._pos + read_len)

        # Aligned blocks
        if n >= align:
            count, n = divmod(n, align)

            read_len = count * align
            actual_read = self._readinto(self._pos, b[:read_len])
            b = b[actual_read:]

            total_read += actual_read
            self._set_pos(self._pos + read_len)

        # Misaligned remaining bytes
        if n > 0:
            self._fill_buf()

            buffer_pos = self._pos - self._pos_align
            buffer_remaining = max(0, min(align, self._buf_size) - buffer_pos)
            read_len = min(n, buffer_remaining)

            b[:read_len] = self._buf[:read_len]

            total_read += read_len
            self._set_pos(self._pos + read_len)

        return total_read

    def _read(self, offset: int, length: int) -> bytes:
        """Provide an aligned ``read`` implementation for this stream."""
        raise NotImplementedError("_read needs to be implemented by subclass")

    def _readinto(self, offset: int, buf: memoryview) -> int:
        """Provide an aligned ``readinto`` implementation for this stream.

        For backwards compatibility, ``AlignedStream`` provides a default ``_readinto`` implementation, implemented in `_readinto_fallback`, that
        falls back on ``_read``. However, subclasses should override the ``_readinto`` method instead of ``_readinto_fallback``.
        """
        return self._readinto_fallback(offset, buf)

    def _readinto_fallback(self, offset: int, buf: bytearray) -> int:
        """``_readinto`` fallback on ``_read``."""
        read_len = len(buf)
        result = self._read(offset, read_len)
        length = len(result)

        if length > read_len:
            raise IOError(f"_read returned more bytes than requested, wanted {read_len} and returned {length}")

        buf[:length] = result
        return length

    def readall(self) -> bytes:
        """Read until end of stream."""
        if self.size is not None:
            # If we have a known stream size, we can do a more optimized read
            return self.read(self.size - self._pos)

        with self._read_lock:
            result = bytearray()

            if self._buf:
                # Drain the buffer first
                buffer_pos = self._pos - self._pos_align
                buffer_remaining = max(0, min(self.align, self._buf_size) - buffer_pos)
                result += self._buf[buffer_pos : buffer_pos + buffer_remaining]

                self._set_pos(self._pos + buffer_remaining)

            # Read the remaining bytes
            try:
                # Check if our stream implementation has a _read we can use
                result += self._read(self._pos, -1)
            except NotImplementedError:
                # Otherwise call _readinto a bunch of times
                buf = bytearray(io.DEFAULT_BUFFER_SIZE)

                while n := self._readinto(self._pos, buf):
                    result += buf[:n]
                    self._set_pos(self._pos + n)

            return bytes(result)

    def readoffset(self, offset: int, length: int) -> bytes:
        """Convenience method to read from a given offset."""
        self.seek(offset)
        return self.read(length)

    def peek(self, n: int = 0) -> bytes:
        """Convenience method to peek from the current offset without advancing the stream position."""
        pos = self._pos
        data = self.read(n)
        self._set_pos(pos)
        return data

    def close(self) -> None:
        """Close the stream. Does nothing by default."""
        pass


class RangeStream(AlignedStream):
    """Create a stream with a specific range from another file-like object.

    ASCII representation::

        Source file-like object
        |................................................|
                RangeStream with offset and size
                |............................|

    Args:
        fh: The source file-like object.
        offset: The offset the stream should start from on the source file-like object.
        size: The size the stream should be.
        align: The alignment size.
    """

    def __init__(self, fh: BinaryIO, offset: int, size: int, align: int = STREAM_BUFFER_SIZE):
        super().__init__(size, align)
        self._fh = fh
        self.offset = offset

    def _seek(self, pos: int, whence: int = io.SEEK_SET) -> int:
        if self.size is None and whence == io.SEEK_END:
            pos = self._fh.seek(pos, whence)
            if pos is None:
                pos = self._fh.tell()
            return max(0, pos - self.offset)
        return super()._seek(pos, whence)

    def _read(self, offset: int, length: int) -> bytes:
        # We will generally only end up here from :func:`AlignedStream.readall`
        read_length = min(length, self.size - offset) if self.size else length
        self._fh.seek(self.offset + offset)
        return self._fh.read(read_length)

    def _readinto(self, offset: int, buf: memoryview) -> int:
        if not hasattr(self._fh, "readinto"):
            return self._readinto_fallback(offset, buf)

        self._fh.seek(self.offset + offset)
        return self._fh.readinto(buf)


class RelativeStream(RangeStream):
    """Create a relative stream from another file-like object.

    ASCII representation::

        Source file-like object
        |................................................|
                RelativeStream with offset
                |........................................|

    Args:
        fh: The source file-like object.
        offset: The offset the stream should start from on the source file-like object.
        size: The size the stream should be.
        align: The alignment size.
    """

    def __init__(self, fh: BinaryIO, offset: int, size: Optional[int] = None, align: int = STREAM_BUFFER_SIZE):
        super().__init__(fh, offset, size, align)


class BufferedStream(RelativeStream):
    """Create a buffered stream from another file-like object.

    Optionally start from a specific offset.

    Args:
        fh: The source file-like object.
        offset: The offset the stream should start from.
        size: The size the stream should be.
        align: The alignment size.
    """

    def __init__(self, fh: BinaryIO, offset: int = 0, size: int | None = None, align: int = STREAM_BUFFER_SIZE):
        super().__init__(fh, offset, size, align)


class MappingStream(AlignedStream):
    """Create a stream from multiple mapped file-like objects.

    Args:
        size: The size the stream should be.
        align: The alignment size.
    """

    def __init__(self, size: int | None = None, align: int = STREAM_BUFFER_SIZE):
        super().__init__(size, align)
        self._runs: list[tuple[int, int, BinaryIO, int]] = []

    def add(self, offset: int, size: int, fh: BinaryIO, file_offset: int = 0) -> None:
        """Add a file-like object to the stream.

        Args:
            offset: The offset in the stream this fh maps to.
            size: The size that this mapped fh spans in the stream.
            fh: The file-like object to map.
            file_offset: The offset in the fh to start from.
        """
        self._runs.append((offset, size, fh, file_offset))
        self._runs = sorted(self._runs)
        self._buf_size = 0
        self.size = self._runs[-1][0] + self._runs[-1][1]

    def _get_run_idx(self, offset: int) -> tuple[int, int, BinaryIO, int]:
        """Find a mapping run for a given offset.

        Args:
            offset: The offset to find a mapping for.

        Returns:
            The run tuple if found.

        Raises:
            IOError: If no mapping is found for the given offset.
        """
        for idx, run in enumerate(self._runs):
            if run[0] <= offset < run[0] + run[1]:
                return idx

        raise EOFError(f"No mapping for offset {offset}")

    def _readinto(self, offset: int, buf: memoryview) -> int:
        size = self.size
        runs = self._runs

        run_idx = self._get_run_idx(offset)
        runlist_len = len(self._runs)

        n = 0
        length = len(buf)

        while length > 0:
            if run_idx >= runlist_len:
                # We somehow requested more data than we have runs for
                break

            run_offset, run_size, run_fh, run_file_offset = runs[run_idx]

            if run_offset > offset:
                # We landed in a gap, stop reading
                break

            run_pos = offset - run_offset
            run_remaining = run_size - run_pos

            if run_remaining < 0:
                break

            read_count = min(size - offset, min(run_remaining, length))

            run_fh.seek(run_file_offset + run_pos)
            if hasattr(run_fh, "readinto"):
                n += run_fh.readinto(buf[:read_count])
            else:
                buf[:read_count] = run_fh.read(read_count)
                n += read_count

            offset += read_count
            length -= read_count
            buf = buf[read_count:]
            run_idx += 1

        return n


class RunlistStream(AlignedStream):
    """Create a stream from multiple runs on another file-like object.

    This is common in filesystems, where file data information is stored in "runs".
    A run is a ``(block_offset, block_count)`` tuple, meaning the amount of consecutive blocks from a
    specific starting block. A block_offset of ``None`` represents a sparse run, meaning it must simply
    return all ``\\x00`` bytes.

    Args:
        fh: The source file-like object.
        runlist: The runlist for this stream in block units.
        size: The size of the stream. This can be smaller than the total sum of blocks (to account for slack space).
        block_size: The block size in bytes.
        align: Optional alignment that differs from the block size, otherwise ``block_size`` is used as alignment.
    """

    def __init__(
        self,
        fh: BinaryIO,
        runlist: list[tuple[int, int]],
        size: int,
        block_size: int,
        align: Optional[int] = None,
    ):
        super().__init__(size, align or block_size)

        if isinstance(fh, RunlistStream):
            self._fh = fh._fh
        else:
            self._fh = fh

        self._runlist = []
        self._runlist_offsets = []

        self.runlist = runlist
        self.block_size = block_size
        self._has_readinto = hasattr(self._fh, "readinto")

    @property
    def runlist(self) -> list[tuple[int, int]]:
        return self._runlist

    @runlist.setter
    def runlist(self, runlist: list[tuple[int, int]]) -> None:
        self._runlist = runlist
        self._runlist_offsets = []

        offset = 0
        # Create a list of starting offsets for each run so we can bisect that quickly when reading
        for _, block_count in self._runlist:
            if offset != 0:
                self._runlist_offsets.append(offset)
            offset += block_count

        self._buf_size = 0

    def _readinto(self, offset: int, buf: memoryview) -> int:
        fh = self._fh
        size = self.size
        runlist = self.runlist
        runlist_offsets = self._runlist_offsets
        block_size = self.block_size

        block_offset = offset // self.block_size
        run_idx = bisect_right(self._runlist_offsets, block_offset)
        runlist_len = len(self.runlist)

        n = 0
        length = len(buf)

        while length > 0:
            if run_idx >= runlist_len:
                # We somehow requested more data than we have runs for
                break

            # If run_idx == 0, we only have a single run
            run_block_pos = 0 if run_idx == 0 else runlist_offsets[run_idx - 1]
            run_block_offset, run_block_count = runlist[run_idx]

            run_size = run_block_count * block_size
            run_pos = offset - run_block_pos * block_size
            run_remaining = run_size - run_pos

            # Sometimes the self.size is way larger than what we actually have runs for?
            # Stop reading if we reach a negative run_remaining
            if run_remaining < 0:
                break

            read_count = min(size - offset, min(run_remaining, length))

            # Sparse run
            if run_block_offset is None:
                buf[:read_count] = b"\x00" * read_count
                n += read_count
            else:
                fh.seek(run_block_offset * block_size + run_pos)
                if self._has_readinto:
                    n += fh.readinto(buf[:read_count])
                else:
                    buf[:read_count] = fh.read(read_count)
                    n += read_count

            offset += read_count
            length -= read_count
            buf = buf[read_count:]
            run_idx += 1

        return n


class OverlayStream(AlignedStream):
    """Create a stream from another file-like object with the ability to overlay other streams or bytes.

    Useful for patching large file-like objects without having to cache the entire contents.
    First wrap the original stream in this class, and then call ``add()`` with the offset and data to overlay.

    Args:
        fh: The source file-like object.
        size: The size the stream should be.
        align: The alignment size.
    """

    def __init__(self, fh: BinaryIO, size: int | None = None, align: int = STREAM_BUFFER_SIZE):
        super().__init__(size, align)
        self._fh = fh
        self.overlays: dict[int, tuple[int, BinaryIO]] = {}
        self._lookup: list[int] = []
        self._has_readinto = hasattr(self._fh, "readinto")

    def add(self, offset: int, data: bytes | BinaryIO, size: int | None = None) -> None:
        """Add an overlay at the given offset.

        Args:
            offset: The offset in bytes to add an overlay at.
            data: The bytes or file-like object to overlay
            size: Optional size specification of the overlay, if it can't be inferred.
        """
        if not hasattr(data, "read"):
            size = size or len(data)
            data = io.BytesIO(data)
        elif size is None:
            size = data.size if hasattr(data, "size") else data.seek(0, io.SEEK_END)

        if not size:
            return None

        if size < 0:
            raise ValueError("Size must be positive")

        # Check if there are overlapping overlays
        for other_offset, (other_size, _) in self.overlays.items():
            if other_offset < offset + size and offset < other_offset + other_size:
                raise ValueError(f"Overlap with existing overlay: ({other_offset, other_size})")

        self.overlays[offset] = (size, data)
        self._lookup.append(offset)
        self._lookup.sort()

        # Clear the buffer if we add an overlay at our current position
        if self._buf_size and (self._pos_align <= offset + size and offset <= self._pos_align + self.align):
            self._buf_size = 0

        return self

    def _readinto(self, offset: int, buf: memoryview) -> int:
        fh = self._fh
        overlays = self.overlays
        lookup = self._lookup

        overlay_len = len(overlays)
        overlay_idx = bisect_left(lookup, offset)

        n = 0
        length = len(buf)

        while length > 0:
            prev_overlay_offset = None if overlay_idx == 0 else lookup[overlay_idx - 1]
            next_overlay_offset = None if overlay_idx >= overlay_len else lookup[overlay_idx]

            if prev_overlay_offset is not None:
                prev_overlay_size, prev_overlay_data = overlays[prev_overlay_offset]
                prev_overlay_end = prev_overlay_offset + prev_overlay_size

                if prev_overlay_end > offset:
                    # Currently in an overlay
                    offset_in_prev_overlay = offset - prev_overlay_offset
                    prev_overlay_remaining = prev_overlay_size - offset_in_prev_overlay
                    prev_overlay_read_size = min(length, prev_overlay_remaining)

                    prev_overlay_data.seek(offset_in_prev_overlay)
                    buf[:prev_overlay_read_size] = prev_overlay_data.read(prev_overlay_read_size)
                    n += prev_overlay_read_size

                    offset += prev_overlay_read_size
                    length -= prev_overlay_read_size
                    buf = buf[prev_overlay_read_size:]

            if length == 0:
                break

            if next_overlay_offset:
                next_overlay_size, next_overlay_data = overlays[next_overlay_offset]
                gap_to_next_overlay = next_overlay_offset - offset

                if 0 <= gap_to_next_overlay < length:
                    if gap_to_next_overlay:
                        fh.seek(offset)
                        if self._has_readinto:
                            n += fh.readinto(buf[:gap_to_next_overlay])
                        else:
                            buf[:gap_to_next_overlay] = fh.read(gap_to_next_overlay)
                            n += gap_to_next_overlay
                        buf = buf[gap_to_next_overlay:]

                    # read remaining from overlay
                    next_overlay_read_size = min(next_overlay_size, length - gap_to_next_overlay)
                    next_overlay_data.seek(0)
                    buf[:next_overlay_read_size] = next_overlay_data.read(next_overlay_read_size)
                    n += next_overlay_read_size

                    offset += next_overlay_read_size + gap_to_next_overlay
                    length -= next_overlay_read_size + gap_to_next_overlay
                    buf = buf[next_overlay_read_size + gap_to_next_overlay :]
                else:
                    # Next overlay is too far away, complete read
                    fh.seek(offset)
                    if self._has_readinto:
                        n += fh.readinto(buf[:length])
                    else:
                        buf[:length] = fh.read(length)
                        n += length
                    break
            else:
                # No next overlay, complete read
                fh.seek(offset)
                if self._has_readinto:
                    n += fh.readinto(buf[:length])
                else:
                    buf[:length] = fh.read(length)
                    n += length
                break

            overlay_idx += 1

        return n


class ZlibStream(AlignedStream):
    """Create a zlib stream from another file-like object.

    Basically the same as ``gzip.GzipFile`` but for raw zlib streams.
    Due to the nature of zlib streams, seeking backwards requires resetting the decompression context.

    Args:
        fh: The source file-like object.
        size: The size the stream should be.
    """

    def __init__(self, fh: BinaryIO, size: int | None = None, align: int = STREAM_BUFFER_SIZE, **kwargs):
        self._fh = fh

        self._zlib = None
        self._zlib_args = kwargs
        self._zlib_offset = 0
        self._zlib_prepend = b""
        self._zlib_prepend_offset = None
        self._rewind()

        super().__init__(size, align)

    def _rewind(self) -> None:
        self._fh.seek(0)
        self._zlib = zlib.decompressobj(**self._zlib_args)
        self._zlib_offset = 0
        self._zlib_prepend = b""
        self._zlib_prepend_offset = None

    def _seek_zlib(self, offset: int) -> None:
        if offset < self._zlib_offset:
            self._rewind()

        while self._zlib_offset < offset:
            read_size = min(offset - self._zlib_offset, self.align)
            if self._read_zlib(read_size) == b"":
                break

    def _read_fh(self, length: int) -> bytes:
        if self._zlib_prepend_offset is None:
            return self._fh.read(length)

        if self._zlib_prepend_offset + length <= len(self._zlib_prepend):
            offset = self._zlib_prepend_offset
            self._zlib_prepend_offset += length
            return self._zlib_prepend[offset : self._zlib_prepend_offset]

        offset = self._zlib_prepend_offset
        self._zlib_prepend_offset = None
        return self._zlib_prepend[offset:] + self._fh.read(length - len(self._zlib_prepend) + offset)

    def _read_zlib(self, length: int) -> bytes:
        if length < 0:
            return self.readall()

        result = []
        while length > 0:
            buf = self._read_fh(io.DEFAULT_BUFFER_SIZE)
            decompressed = self._zlib.decompress(buf, length)

            if self._zlib.unconsumed_tail != b"":
                self._zlib_prepend = self._zlib.unconsumed_tail
                self._zlib_prepend_offset = 0

            if buf == b"":
                break

            result.append(decompressed)
            length -= len(decompressed)

        buf = b"".join(result)
        self._zlib_offset += len(buf)
        return buf

    def _read(self, offset: int, length: int) -> bytes:
        self._seek_zlib(offset)
        return self._read_zlib(length)

    def readall(self) -> bytes:
        self._seek_zlib(self.tell())

        chunks = []
        # sys.maxsize means the max length of output buffer is unlimited,
        # so that the whole input buffer can be decompressed within one
        # .decompress() call.
        while data := self._read_zlib(sys.maxsize):
            chunks.append(data)

        return b"".join(chunks)
