"""Compact XPRESS9 compression and decompression (ntdll format 0x0005).

Implements the decompressor and compressor for the undocumented ntdll.dll
compression format 0x0005, introduced in Windows Server 2022 (Build 20348).
Uses the same canonical-Huffman LZ77 engine as the ESE XPRESS9 codec
(:mod:`dissect.util.compression.lzxpress9`) but with a streamlined 10-byte
header instead of XPRESS9's 32-byte block header.

On-disk layout::

  bytes 0-3:   magic ``0xC039E510`` (LE u32)
  bytes 4-5:   params (LE u16) -- bits 0-2: window_log index; bit 3: mode
  bytes 6-9:   control (LE u32) -- bits 0-27: payload bit count (data + 32-bit CRC);
               bit 29: compressed flag; bit 31: end-of-stream
  bytes 10+:   payload (ceil(payload_bits / 8) bytes)
  trailing:    CRC-32C of original plaintext (32 bits, inside the payload area)

Reverse-engineered from ``ntdll.dll`` Build 20348 (decompressor at RVA 0x111810).

Reference implementation: ntcompress (https://github.com/StrongWind1/ntcompress).
"""

from __future__ import annotations

import struct
from typing import Final

from dissect.util.compression.lzxpress9 import (
    _LONG_LENGTH_ALPHABET_SIZE,
    _MAX_LONG_LENGTH,
    _MAX_MTF,
    _MAX_SHORT_LENGTH,
    _MAX_SHORT_LENGTH_LOG,
    _BitReader,
    _CanonicalHuffman,
    _copy_match,
    _decode_coded_lengths,
    _read_match_length,
    _take_mtf_offset,
)
from dissect.util.exceptions import CorruptDataError
from dissect.util.hash import crc32c as _crc32c_mod

_crc32c = _crc32c_mod.crc32c

MAGIC: Final = 0xC039E510
"""Block magic -- distinct from XPRESS9's ``0x4E86D72A``."""

HEADER_SIZE: Final = 10
"""Fixed header size: 4 (magic) + 2 (params) + 4 (control)."""

_WINDOW_LOG_TABLE: Final = (12, 13, 14, 16, 18, 20, 22, 24)

_PTR_MIN_MATCH: Final = 3
_MTF_MIN_MATCH: Final = 2


def _short_alphabet_size(window_log: int) -> int:
    return (window_log + 16 + _MAX_MTF) << _MAX_SHORT_LENGTH_LOG


def _decode_table_2bit(reader: _BitReader, alphabet_size: int) -> _CanonicalHuffman:
    """Decode a Huffman table with the compact 2-bit mode prefix.

    Modes: 0 = stored (flat code lengths), 2 = Huffman-coded, 1/3 = error.
    """
    mode = reader.read(2)
    if mode == 0:
        msb = alphabet_size.bit_length() - 1
        short_count = (1 << (msb + 1)) - alphabet_size
        return _CanonicalHuffman([msb] * short_count + [msb + 1] * (alphabet_size - short_count))
    if mode == 2:
        return _CanonicalHuffman(_decode_coded_lengths(reader, alphabet_size, _MAX_SHORT_LENGTH))
    raise CorruptDataError(f"compact XPRESS9: unsupported table mode {mode}")


def decompress(src: bytes, *, verify: bool = True) -> bytes:
    """Decompress a compact XPRESS9 stream (ntdll format 0x0005).

    Args:
        src: The compressed stream including the 10-byte header.
        verify: When True (default), verify the trailing CRC-32C.

    Returns:
        The decompressed plaintext.

    Raises:
        CorruptDataError: Stream is corrupt, truncated, or CRC mismatch.
    """
    if len(src) < HEADER_SIZE:
        raise CorruptDataError(f"compact XPRESS9 too short: {len(src)} < {HEADER_SIZE}")

    magic = struct.unpack_from("<I", src, 0)[0]
    if magic != MAGIC:
        raise CorruptDataError(f"bad compact XPRESS9 magic 0x{magic:08x}")

    params = struct.unpack_from("<H", src, 4)[0]
    control = struct.unpack_from("<I", src, 6)[0]

    window_log = _WINDOW_LOG_TABLE[params & 0x07]
    payload_bits = control & 0x0FFF_FFFF
    compressed = bool(control & (1 << 29))

    payload_bytes = -(-payload_bits // 8)
    if len(src) < HEADER_SIZE + payload_bytes:
        raise CorruptDataError("compact XPRESS9 stream truncated")

    payload = src[HEADER_SIZE : HEADER_SIZE + payload_bytes]

    if not compressed:
        data_bits = payload_bits - 32
        if data_bits & 7:
            raise CorruptDataError("compact XPRESS9 uncompressed payload not byte-aligned")
        plain = payload[: data_bits >> 3]
    else:
        comp_bits = payload_bits - 32
        short_alpha = _short_alphabet_size(window_log)

        reader = _BitReader(payload)
        short_table = _decode_table_2bit(reader, short_alpha)
        long_table = _decode_table_2bit(reader, _LONG_LENGTH_ALPHABET_SIZE)

        out = bytearray()
        mtf: list[int] = []
        last_was_ptr = 0

        while reader.bits_consumed < comp_bits:
            symbol = short_table.decode(reader)
            if symbol < 256:
                out.append(symbol)
                last_was_ptr = 0
                continue

            symbol -= 256
            length = symbol & (_MAX_SHORT_LENGTH - 1)
            symbol >>= _MAX_SHORT_LENGTH_LOG

            if length == _MAX_SHORT_LENGTH - 1:
                length = _read_match_length(reader, long_table)

            if symbol < _MAX_MTF:
                length += _MTF_MIN_MATCH
                offset = _take_mtf_offset(mtf, symbol, last_was_ptr=bool(last_was_ptr))
            else:
                length += _PTR_MIN_MATCH
                msb = symbol - _MAX_MTF
                offset = reader.read(msb) + (1 << msb) if msb > 0 else 1
                if len(mtf) < _MAX_MTF:
                    mtf.insert(0, offset)
                else:
                    mtf.insert(0, offset)
                    mtf.pop()

            if offset > len(out):
                raise CorruptDataError(f"compact XPRESS9 match offset {offset} before start at {len(out)}")
            last_was_ptr = 1
            _copy_match(out, offset, length)

        plain = bytes(out)

    if verify:
        crc_byte_start = -(-((payload_bits - 32)) // 8)
        if crc_byte_start + 4 <= len(payload):
            expected = struct.unpack_from("<I", payload, crc_byte_start)[0]
            actual = _crc32c(plain)
            if expected != actual:
                raise CorruptDataError(f"compact XPRESS9 CRC-32C mismatch: 0x{expected:08x} vs 0x{actual:08x}")

    return plain


def compress(src: bytes) -> bytes:
    """Compress data into a compact XPRESS9 stream (ntdll format 0x0005).

    Uses uncompressed (literal) mode for simplicity and correctness. The output
    is a valid stream that ``RtlDecompressBufferEx(0x0005)`` accepts, though it
    does not achieve any size reduction.

    Args:
        src: The plaintext to compress.

    Returns:
        The compressed stream including header and CRC-32C.
    """
    crc = _crc32c(src)
    crc_bytes = struct.pack("<I", crc)
    payload = src + crc_bytes
    payload_bits = len(payload) * 8
    control = payload_bits | (1 << 31)
    header = struct.pack("<IHI", MAGIC, 0x4007, control)
    return header + payload
