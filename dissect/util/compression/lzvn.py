"""LZVN compression and decompression.

LZVN is an Apple LZ77-type compression. APFS can use it for compressed files, and LZFSE uses it for small inputs.

References:
    - https://github.com/lzfse/lzfse
"""

from __future__ import annotations

import io
import struct
from collections import defaultdict, deque
from typing import BinaryIO

MIN_MATCH = 3
WINDOW = 65535
CHAIN_LIMIT = 128

# The longest literal and match of an opcode that has its own length byte
MAX_LITERAL = 271
MAX_MATCH = 271

# The end of stream opcode, which is followed by 7 zero bytes
END_OF_STREAM = b"\x06" + bytes(7)

# fmt: off
OP_SML_D = (
      0,   1,   2,   3,   4,   5,   8,   9,  10,  11,  12,  13,  16,  17,  18,  19,
     20,  21,  24,  25,  26,  27,  28,  29,  32,  33,  34,  35,  36,  37,  40,  41,
     42,  43,  44,  45,  48,  49,  50,  51,  52,  53,  56,  57,  58,  59,  60,  61,
     64,  65,  66,  67,  68,  69,  72,  73,  74,  75,  76,  77,  80,  81,  82,  83,
     84,  85,  88,  89,  90,  91,  92,  93,  96,  97,  98,  99, 100, 101, 104, 105,
    106, 107, 108, 109, 128, 129, 130, 131, 132, 133, 136, 137, 138, 139, 140, 141,
    144, 145, 146, 147, 148, 149, 152, 153, 154, 155, 156, 157, 192, 193, 194, 195,
    196, 197, 200, 201, 202, 203, 204, 205,
)
OP_MED_D = (
    160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175,
    176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191,
)
OP_LRG_D = (
      7,  15,  23,  31,  39,  47,  55,  63,  71,  79,  87,  95, 103, 111, 135, 143,
    151, 159, 199, 207,
)
OP_PRE_D = (
     70,  78,  86,  94, 102, 110, 134, 142, 150, 158, 198, 206,
)
OP_SML_M = (
    241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255,
)
OP_LRG_M = (
    240,
)
OP_SML_L = (
    225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
)
OP_LRG_L = (
    224,
)
OP_NOP = (
     14,  22,
)
OP_EOS = (
    6,
)
OP_UDEF = (
     30,  38,  46,  54,  62, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121,
    122, 123, 124, 125, 126, 127, 208, 209, 210, 211, 212, 213, 214, 215, 216,
    217, 218, 219, 220, 221, 222, 223,
)
# fmt: on

_H = struct.Struct("<H")


def _put_literal(dst: bytearray, literal: bytes) -> None:
    for i in range(0, len(literal), MAX_LITERAL):
        chunk = literal[i : i + MAX_LITERAL]
        if len(chunk) < 16:
            dst.append(0xE0 | len(chunk))
        else:
            dst += bytes((0xE0, len(chunk) - 16))
        dst += chunk


def compress(src: bytes | BinaryIO) -> bytes:
    """LZVN compress from a file-like object or bytes.

    Args:
        src: File-like object or bytes to compress.

    Returns:
        The compressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    data = src.read()
    dst = bytearray()

    chains = defaultdict(lambda: deque(maxlen=CHAIN_LIMIT))
    literal_offset = 0
    offset = 0
    previous_distance = 0

    while offset < len(data):
        length = 0
        distance = 0

        for match_offset in reversed(chains.get(data[offset : offset + MIN_MATCH], ())):
            if offset - match_offset > WINDOW:
                break

            match_length = MIN_MATCH
            while (
                offset + match_length < len(data) and data[match_offset + match_length] == data[offset + match_length]
            ):
                match_length += 1

            if match_length > length:
                length = match_length
                distance = offset - match_offset

        if length == 0:
            # Literal, which is written together with the literals up to the next match
            chains[data[offset : offset + MIN_MATCH]].append(offset)
            offset += 1
            continue

        # Up to 3 literals are part of the match opcode, more get their own opcode
        literal = data[literal_offset:offset]
        if len(literal) > 3:
            _put_literal(dst, literal)
            literal = b""

        # The match opcode has room for fewer match bytes the more literals it has, the rest of the match follows in
        # match opcodes that reuse the distance
        match_length = min(length, 10 - 2 * len(literal))
        remaining = length - match_length

        if distance == previous_distance:
            if not literal:
                dst.append(0xF0 | match_length)
            else:
                dst.append((len(literal) << 6) | ((match_length - 3) << 3) | 6)
        elif distance < 0x600:
            dst.append((len(literal) << 6) | ((match_length - 3) << 3) | (distance >> 8))
            dst.append(distance & 0xFF)
        elif distance >= 0x4000 or remaining == 0 or length > 34:
            dst.append((len(literal) << 6) | ((match_length - 3) << 3) | 7)
            dst += _H.pack(distance)
        else:
            # Medium distance, which has room for the whole match
            remaining = 0
            dst.append(0xA0 | (len(literal) << 3) | ((length - 3) >> 2))
            dst += _H.pack((distance << 2) | ((length - 3) & 3))
        dst += literal

        for i in range(0, remaining, MAX_MATCH):
            size = min(remaining - i, MAX_MATCH)
            if size < 16:
                dst.append(0xF0 | size)
            else:
                dst += bytes((0xF0, size - 16))

        for i in range(offset, offset + length):
            chains[data[i : i + MIN_MATCH]].append(i)
        offset += length
        literal_offset = offset
        previous_distance = distance

    _put_literal(dst, data[literal_offset:])
    dst += END_OF_STREAM

    return bytes(dst)


def decompress(src: bytes | BinaryIO) -> bytes:
    """LZVN decompress from a file-like object or bytes.

    Decompresses until EOF or EOS of the input data.

    Args:
        src: File-like object or bytes to decompress.

    Returns:
        The decompressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    offset = src.tell()
    src.seek(0, io.SEEK_END)
    src_size = src.tell() - offset
    src.seek(offset)

    dst = bytearray()

    opc_len = 0

    L = None
    M = None
    D = 0

    while src_size > 0:
        opc = src.read(1)[0]

        if opc in OP_SML_D:
            # "small distance": This opcode has the structure LLMMMDDD DDDDDDDD LITERAL
            # where the length of literal (0-3 bytes) is encoded by the high 2 bits of
            # the first byte. We first extract the literal length so we know how long
            # the opcode is, then check that the source can hold both this opcode and
            # at least one byte of the next (because any valid input stream must be
            # terminated with an eos token).
            opc_len = 2
            L = _extract(opc, 8, 6, 2)
            M = _extract(opc, 8, 3, 3) + 3

            if src_size <= opc_len + L:
                break

            D = _extract(opc, 8, 0, 3) << 8 | src.read(1)[0]

        elif opc in OP_MED_D:
            # "medium distance": This is a minor variant of the "small distance"
            # encoding, where we will now use two extra bytes instead of one to encode
            # the restof the match length and distance. This allows an extra two bits
            # for the match length, and an extra three bits for the match distance. The
            # full structure of the opcode is 101LLMMM DDDDDDMM DDDDDDDD LITERAL.
            opc_len = 3
            L = _extract(opc, 8, 3, 2)

            if src_size <= opc_len + L:
                break

            (opc23,) = _H.unpack(src.read(2))
            M = (_extract(opc, 8, 0, 3) << 2 | _extract(opc23, 16, 0, 2)) + 3
            D = _extract(opc23, 16, 2, 14)

        elif opc in OP_LRG_D:
            # "large distance": This is another variant of the "small distance"
            # encoding, where we will now use two extra bytes to encode the match
            # distance, which allows distances up to 65535 to be represented. The full
            # structure of the opcode is LLMMM111 DDDDDDDD DDDDDDDD LITERAL.
            opc_len = 3
            L = _extract(opc, 8, 6, 2)
            M = _extract(opc, 8, 3, 3) + 3

            if src_size <= opc_len + L:
                break

            (D,) = _H.unpack(src.read(2))

        elif opc in OP_PRE_D:
            # "previous distance": This opcode has the structure LLMMM110, where the
            # length of the literal (0-3 bytes) is encoded by the high 2 bits of the
            # first byte. We first extract the literal length so we know how long
            # the opcode is, then check that the source can hold both this opcode and
            # at least one byte of the next (because any valid input stream must be
            # terminated with an eos token).
            opc_len = 1
            L = _extract(opc, 8, 6, 2)
            M = _extract(opc, 8, 3, 3) + 3

            if src_size <= opc_len + L:
                break

        elif opc in OP_SML_M:
            # "small match": This opcode has no literal, and uses the previous match
            # distance (i.e. it encodes only the match length), in a single byte as
            # 1111MMMM.
            opc_len = 1
            L = None
            M = _extract(opc, 8, 0, 4)

            if src_size <= opc_len:
                break

        elif opc in OP_LRG_M:
            # "large match": This opcode has no literal, and uses the previous match
            # distance (i.e. it encodes only the match length). It is encoded in two
            # bytes as 11110000 MMMMMMMM.  Because matches smaller than 16 bytes can
            # be represented by sml_m, there is an implicit bias of 16 on the match
            # length; the representable values are [16,271].
            opc_len = 2
            L = None

            if src_size <= opc_len:
                break

            M = src.read(1)[0] + 16

        elif opc in OP_SML_L:
            # "small literal": This opcode has no match, and encodes only a literal
            # of length up to 15 bytes. The format is 1110LLLL LITERAL.
            opc_len = 1
            L = _extract(opc, 8, 0, 4)
            M = None

        elif opc in OP_LRG_L:
            # "large literal": This opcode has no match, and uses the previous match
            # distance (i.e. it encodes only the match length). It is encoded in two
            # bytes as 11100000 LLLLLLLL LITERAL.  Because literals smaller than 16
            # bytes can be represented by sml_l, there is an implicit bias of 16 on
            # the literal length; the representable values are [16,271].
            opc_len = 2

            if src_size <= opc_len:
                break

            L = src.read(1)[0] + 16
            M = None

        elif opc in OP_NOP:
            opc_len = 1
            L = None
            M = None

            if src_size <= opc_len:
                break

        elif opc in OP_EOS:
            break

        elif opc in OP_UDEF:
            raise ValueError("Undefined opcode")

        # Update remaining source size
        src_size -= opc_len

        # Copy literal
        if L is not None:
            src_size -= L
            dst += src.read(L)

        # Match
        if M is not None:
            if len(dst) < D or D == 0:
                raise ValueError("Invalid match distance")

            if M <= D:
                dst += dst[-D : (-D + M) or None]
            else:
                # The match overlaps the output it produces, so it repeats the last D bytes
                chunk = dst[-D:]
                dst += chunk * (M // D)
                dst += chunk[: M % D]

    return bytes(dst)


def _extract(container: int, container_width: int, lsb: int, width: int) -> int:
    if width == container_width:
        return container
    return (container >> lsb) & ((1 << width) - 1)
