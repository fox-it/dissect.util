# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-frs2/8cb5bae9-edf3-4833-9f0a-9d7e24218d3d
# https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-XCA/[MS-XCA].pdf
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


def decompress(src: bytes | BinaryIO) -> bytes:
    """LZXPRESS decompress from a file-like object or bytes.

    Decompresses until EOF of the input data.

    Args:
        src: File-like object or bytes to decompress.

    Returns:
        The decompressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    dst = bytearray()

    start_offset = src.tell()
    src.seek(0, io.SEEK_END)
    size = src.tell() - start_offset
    src.seek(start_offset, io.SEEK_SET)

    while src.tell() - start_offset < size:
        decoder = _build_decoder(src.read(256))

        # The reference decoder keeps at least 16 bits buffered after every removal
        # The extra length bytes and the next chunk are read directly after these buffered bits, so we do the same
        stream = BitStream(src, word_size=2, byteorder="little")

        chunk_size = 0
        while chunk_size < 65536 and src.tell() - start_offset < size:
            symbol = decoder.decode(stream)
            stream.ensure(16)

            if symbol < 256:
                dst.append(symbol)
                chunk_size += 1
            else:
                symbol -= 256
                length = symbol & 0x0F
                symbol >>= 4

                offset = (1 << symbol) + stream.read(symbol)

                if length == 15:
                    length = ord(stream.read_bytes(1)) + 15

                    if length == 270:
                        length = int.from_bytes(stream.read_bytes(2), "little")

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

                chunk_size += length

    return bytes(dst)
