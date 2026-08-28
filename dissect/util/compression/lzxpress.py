"""LZXPRESS plain compression and decompression per [MS-XCA] S2.3-2.4."""

from __future__ import annotations

import io
import struct
from typing import BinaryIO

# --- Wire constants ([MS-XCA] S2.3 / S2.4) ---

_MIN_MATCH = 3
_MAX_OFFSET = 8192
_MAX_MATCH_LENGTH = 0xFFFF_FFFF
_FLAG_BITS = 32
_TOKEN_LENGTH_LIMIT = 7
_NIBBLE_LIMIT = 15
_BYTE_LIMIT = 255
_WORD_LIMIT = 1 << 16
_LADDER_FLOOR = _NIBBLE_LIMIT + _TOKEN_LENGTH_LIMIT
_MAX_CHAIN = 64
_CHAIN_PRUNE = 256


def decompress(src: bytes | BinaryIO, max_size: int | None = None) -> bytes:
    """LZXPRESS decompress from a file-like object or bytes.

    Args:
        src: File-like object or bytes to decompress.
        max_size: Optional maximum output size in bytes. When set, raises
            ValueError if the decompressed output would exceed this limit.

    Returns:
        The decompressed data.

    Raises:
        ValueError: If the output exceeds ``max_size`` or the stream contains an invalid match length.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    offset = src.tell()
    src.seek(0, io.SEEK_END)
    size = src.tell() - offset
    src.seek(offset)

    dst = bytearray()

    buffered_flags = 0
    buffered_flags_count = 0
    last_length_half_byte = 0

    while src.tell() - offset < size:
        if buffered_flags_count == 0:
            buffered_flags = struct.unpack("<I", src.read(4))[0]
            buffered_flags_count = 32

        buffered_flags_count -= 1
        if buffered_flags & (1 << buffered_flags_count) == 0:
            if max_size is not None and len(dst) >= max_size:
                raise ValueError(f"decompressed output exceeds max_size of {max_size}")
            dst.append(ord(src.read(1)))
        else:
            if src.tell() - offset == size:
                break

            match = struct.unpack("<H", src.read(2))[0]
            match_offset, match_length = divmod(match, 8)
            match_offset += 1

            if match_length == 7:
                if last_length_half_byte == 0:
                    last_length_half_byte = src.tell()
                    match_length = ord(src.read(1)) % 16
                else:
                    rewind = src.tell()
                    src.seek(last_length_half_byte)
                    match_length = ord(src.read(1)) // 16
                    src.seek(rewind)
                    last_length_half_byte = 0

                if match_length == 15:
                    match_length = ord(src.read(1))
                    if match_length == 255:
                        match_length = struct.unpack("<H", src.read(2))[0]
                        if match_length == 0:
                            match_length = struct.unpack("<I", src.read(4))[0]

                        if match_length < 15 + 7:
                            raise ValueError("wrong match length")

                        match_length -= 15 + 7
                    match_length += 15
                match_length += 7
            match_length += 3

            if max_size is not None and len(dst) + match_length > max_size:
                raise ValueError(f"decompressed output exceeds max_size of {max_size}")

            remaining = match_length
            while remaining > 0:
                match_size = min(remaining, match_offset)
                dst += dst[-match_offset : (-match_offset + match_size) or None]
                remaining -= match_size

    return bytes(dst)


# --- Compression ([MS-XCA] S2.3.4) ---


class _Encoder:
    """Mutable output buffer for the [MS-XCA] S2.3.4 encoder."""

    def __init__(self) -> None:
        self.out = bytearray(4)
        self.flags = 0
        self.flag_count = 0
        self.flag_pos = 0
        self.nibble_pos = -1

    def _push_flag(self, bit: int) -> None:
        """Append one literal/match flag bit; flush the word every 32 bits."""
        self.flags = self.flags << 1 | bit
        self.flag_count += 1
        if self.flag_count == _FLAG_BITS:
            self.out[self.flag_pos : self.flag_pos + 4] = self.flags.to_bytes(4, "little")
            self.flags = 0
            self.flag_count = 0
            self.flag_pos = len(self.out)
            self.out += b"\x00\x00\x00\x00"

    def emit_literal(self, byte: int) -> None:
        """Copy one raw byte to the output under a 0 flag bit."""
        self.out.append(byte)
        self._push_flag(0)

    def _emit_long_length(self, extra: int) -> None:
        """Encode length - 3 - 7 through the nibble/byte/word/dword ladder."""
        if self.nibble_pos < 0:
            self.nibble_pos = len(self.out)
            self.out.append(min(extra, _NIBBLE_LIMIT))
        else:
            self.out[self.nibble_pos] |= min(extra, _NIBBLE_LIMIT) << 4
            self.nibble_pos = -1
        if extra < _NIBBLE_LIMIT:
            return
        extra -= _NIBBLE_LIMIT
        if extra < _BYTE_LIMIT:
            self.out.append(extra)
            return
        self.out.append(_BYTE_LIMIT)
        extra += _LADDER_FLOOR
        if extra < _WORD_LIMIT:
            self.out += extra.to_bytes(2, "little")
        else:
            self.out += b"\x00\x00" + extra.to_bytes(4, "little")

    def emit_match(self, offset: int, length: int) -> None:
        """Encode one match as a 16-bit LE token under a 1 flag bit."""
        token = (offset - 1) << 3
        extra = length - _MIN_MATCH
        if extra < _TOKEN_LENGTH_LIMIT:
            self.out += (token | extra).to_bytes(2, "little")
        else:
            self.out += (token | _TOKEN_LENGTH_LIMIT).to_bytes(2, "little")
            self._emit_long_length(extra - _TOKEN_LENGTH_LIMIT)
        self._push_flag(1)

    def finish(self) -> bytes:
        """Pad the pending flag word with 1-bits and flush it."""
        pad = _FLAG_BITS - self.flag_count
        self.out[self.flag_pos : self.flag_pos + 4] = (self.flags << pad | (1 << pad) - 1).to_bytes(4, "little")
        return bytes(self.out)


def _index(table: dict[bytes, list[int]], data: bytes, pos: int) -> None:
    """Record pos as a future match candidate for its 3-byte prefix."""
    key = data[pos : pos + _MIN_MATCH]
    chain = table.get(key)
    if chain is None:
        table[key] = [pos]
        return
    chain.append(pos)
    if len(chain) > _CHAIN_PRUNE:
        del chain[:-_MAX_CHAIN]


def _match_length(data: bytes, candidate: int, pos: int, limit: int) -> int:
    """Extend a guaranteed 3-byte prefix match as far as it goes."""
    length = _MIN_MATCH
    while length < limit and data[candidate + length] == data[pos + length]:
        length += 1
    return length


def _find_match(data: bytes, pos: int, table: dict[bytes, list[int]]) -> tuple[int, int]:
    """Find the longest match for pos within the last 8192 bytes.

    Returns:
        Tuple of (offset, length), or (0, 0) when no match exists.
    """
    if pos + _MIN_MATCH > len(data):
        return 0, 0
    chain = table.get(data[pos : pos + _MIN_MATCH])
    if chain is None:
        return 0, 0
    limit = min(len(data) - pos, _MAX_MATCH_LENGTH)
    best_offset = 0
    best_length = 0
    for candidate in reversed(chain[-_MAX_CHAIN:]):
        if pos - candidate > _MAX_OFFSET:
            break
        length = _match_length(data, candidate, pos, limit)
        if length > best_length:
            best_offset = pos - candidate
            best_length = length
            if length == limit:
                break
    return best_offset, best_length


def compress(src: bytes | BinaryIO) -> bytes:
    """LZXPRESS compress from a file-like object or bytes.

    Greedy hash-chain match finder per [MS-XCA] S2.3.4.

    Args:
        src: File-like object or bytes to compress.

    Returns:
        The compressed data.
    """
    if hasattr(src, "read"):
        src = src.read()

    data = bytes(src)
    size = len(data)
    encoder = _Encoder()
    table: dict[bytes, list[int]] = {}
    last_key_pos = size - _MIN_MATCH
    pos = 0
    while pos < size:
        offset, length = _find_match(data, pos, table)
        if length:
            for covered in range(pos, min(pos + length, last_key_pos + 1)):
                _index(table, data, covered)
            encoder.emit_match(offset, length)
            pos += length
        else:
            if pos <= last_key_pos:
                _index(table, data, pos)
            encoder.emit_literal(data[pos])
            pos += 1
    return encoder.finish()
