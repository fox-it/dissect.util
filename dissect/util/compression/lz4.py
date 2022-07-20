import struct

from dissect.util.exceptions import CorruptDataError


def get_length(src, length):
    if length != 0xF:
        return length

    while True:
        read_buf = src.read(1)
        if len(read_buf) != 1:
            raise CorruptDataError("EOF at length read")
        len_part = ord(read_buf)
        length += len_part

        if len_part != 0xFF:
            break

    return length


def decompress(src, max_len):
    """LZ4 decompress from a file-like object up to a certain length.

    Args:
        src: File-like object to decompress from.
        max_len: Decompress up to this many result bytes.

    Returns:
        A tuple of the decompressed bytearray and the amount of bytes read.
    """
    dst = bytearray()
    start = src.tell()
    min_match_len = 4

    while True:
        read_buf = src.read(1)
        if len(read_buf) == 0:
            raise CorruptDataError("EOF at reading literal-len")

        token = ord(read_buf)
        literal_len = get_length(src, (token >> 4) & 0xF)

        read_buf = src.read(literal_len)

        if len(read_buf) != literal_len:
            raise CorruptDataError("Not literal data")
        dst.extend(read_buf)

        if len(dst) == max_len:
            break

        read_buf = src.read(2)
        if len(read_buf) == 0:
            token_and = token & 0xF
            if token_and != 0:
                raise CorruptDataError(f"EOF, but match-len > 0: {token_and}")
            break

        if len(read_buf) != 2:
            raise CorruptDataError("Premature EOF")

        (offset,) = struct.unpack("<H", read_buf)

        if offset == 0:
            raise CorruptDataError("Offset can't be 0")

        match_len = get_length(src, (token >> 0) & 0xF)
        match_len += min_match_len

        for _ in range(match_len):
            dst.append(dst[-offset])

    return dst, src.tell() - start
