# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-frs2/8cb5bae9-edf3-4833-9f0a-9d7e24218d3d
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/a8b7cb0a-92a6-4187-a23b-5e14273b96f8
from __future__ import annotations

import io
from typing import BinaryIO

from dissect.util.compression.huffman import HuffmanDecoder
from dissect.util.stream import BitStream


def _build_decoder(buf: bytes) -> HuffmanDecoder:
    if len(buf) != 256:
        raise ValueError("Not enough data for Huffman code tree")

    lengths = []
    for c in buf:
        lengths.append(c & 0x0F)
        lengths.append((c >> 4) & 0x0F)

    decoder = HuffmanDecoder(512, 15)
    decoder.import_lengths(lengths)
    return decoder


def decompress(src: bytes | BinaryIO, size: int | None = None) -> bytes:
    """LZXPRESS Huffman decompress from a file-like object or bytes.

    Decompresses until the decompressed size is reached or, if it's not given, until the end-of-stream symbol.

    The end-of-stream symbol is also a valid match symbol, so without a decompressed size it's only recognized as such
    when nothing but zero bits follow it. Pass the decompressed size whenever it's known.

    Args:
        src: File-like object or bytes to decompress.
        size: The decompressed size, if known.

    Returns:
        The decompressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    dst = bytearray()

    start_offset = src.tell()
    src.seek(0, io.SEEK_END)
    end_offset = src.tell()
    src.seek(start_offset, io.SEEK_SET)

    while end_offset - src.tell() >= 256 and (size is None or len(dst) < size):
        decoder = _build_decoder(src.read(256))

        # The reference decoder keeps at least 16 bits buffered after every removal
        # The extra length bytes and the next block are read directly after these buffered bits, so we do the same
        stream = BitStream(src, word_size=2, byteorder="little")
        stream.ensure(16)

        # Matches can extend past the end of a block, which extends the block
        block_end = len(dst) + 65536
        if size is not None:
            block_end = min(block_end, size)

        while len(dst) < block_end and stream.bits:
            symbol = decoder.decode(stream)
            stream.ensure(16)

            if symbol < 256:
                dst.append(symbol)
                continue

            if symbol == 256 and size is None and src.tell() >= end_offset and not stream.buffer:
                # End-of-stream symbol, the input is fully read and only zero bits remain
                return bytes(dst)

            symbol -= 256
            length = symbol & 0x0F
            symbol >>= 4

            offset = (1 << symbol) + stream.read(symbol)

            if length == 15:
                length = ord(stream.read_bytes(1)) + 15

                if length == 270:
                    length = int.from_bytes(stream.read_bytes(2), "little")

                    if length == 0:
                        length = int.from_bytes(stream.read_bytes(4), "little")

            stream.ensure(16)

            length += 3

            if offset > len(dst):
                raise ValueError("Invalid match distance")

            if length <= offset:
                dst += dst[-offset : (-offset + length) or None]
            else:
                # The match overlaps the output it produces, so it repeats the last offset bytes
                chunk = dst[-offset:]
                dst += chunk * (length // offset)
                dst += chunk[: length % offset]

    return bytes(dst[:size])
