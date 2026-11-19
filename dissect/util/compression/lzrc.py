# References:
# - https://github.com/hrydgard/ppsspp/blob/master/Core/FileSystems/tlzrc.cpp
from __future__ import annotations

import io
import sys
from collections import defaultdict, deque
from typing import BinaryIO

MIN_MATCH = 3
MAX_MATCH = 255
WINDOW = 32768
CHAIN_LIMIT = 128

RANGE_MASK = 0xFFFFFFFF
RANGE_TOP = 0x01000000
PROB_INIT = 0x80
END_OF_STREAM = 0xFF


def _init_probabilities() -> tuple[list[list[int]], ...]:
    return (
        [[PROB_INIT] * 256 for _ in range(8)],  # literal
        [[PROB_INIT] * 51 for _ in range(8)],  # distance bits
        [[PROB_INIT] * 8 for _ in range(44)],  # distance
        [[PROB_INIT] * 8 for _ in range(8)],  # match
        [[PROB_INIT] * 31 for _ in range(8)],  # length
    )


class _RangeDecoder:
    def __init__(self, fh: BinaryIO, code: int):
        self.fh = fh
        self.range = RANGE_MASK
        self.code = code

    def normalize(self) -> None:
        if self.range < RANGE_TOP:
            if not (byte := self.fh.read(1)):
                raise ValueError("Truncated LZRC stream")

            self.range <<= 8
            self.code = (self.code << 8) | byte[0]

    def decode_bit(self, probs: list[int], index: int) -> int:
        self.normalize()

        prob = probs[index]
        bound = (self.range >> 8) * prob
        prob -= prob >> 3

        if self.code < bound:
            self.range = bound
            probs[index] = prob + 31
            return 1

        probs[index] = prob
        self.code -= bound
        self.range -= bound
        return 0

    def decode_bittree(self, probs: list[int], offset: int, limit: int) -> int:
        number = 1
        while number < limit:
            number = (number << 1) | self.decode_bit(probs, offset + number)
        return number

    def decode_number(self, probs: list[int], offset: int, bits: int) -> int:
        # A number is made up of the 2 most significant bits, the direct bits (without a probability model)
        # and the 3 least significant bits
        number = 1

        if bits > 3:
            number = (number << 1) | self.decode_bit(probs, offset + 3)
            if bits > 4:
                number = (number << 1) | self.decode_bit(probs, offset + 3)
                if bits > 5:
                    self.normalize()
                    for _ in range(bits - 5):
                        self.range >>= 1
                        number <<= 1
                        if self.code < self.range:
                            number |= 1
                        else:
                            self.code -= self.range

        if bits > 0:
            number = (number << 1) | self.decode_bit(probs, offset)
            if bits > 1:
                number = (number << 1) | self.decode_bit(probs, offset + 1)
                if bits > 2:
                    number = (number << 1) | self.decode_bit(probs, offset + 2)

        return number


class _RangeEncoder:
    def __init__(self):
        self.low = 0
        self.range = RANGE_MASK
        self.cache = 0
        self.cache_size = 1
        self.dst = bytearray()

    def shift_low(self) -> None:
        # Bytes are held back for as long as a carry can still propagate into them
        if self.low < 0xFF000000 or self.low > RANGE_MASK:
            carry = self.low >> 32
            byte = self.cache
            while self.cache_size:
                self.dst.append((byte + carry) & 0xFF)
                byte = 0xFF
                self.cache_size -= 1
            self.cache = (self.low >> 24) & 0xFF

        self.cache_size += 1
        self.low = (self.low << 8) & RANGE_MASK

    def normalize(self) -> None:
        if self.range < RANGE_TOP:
            self.range <<= 8
            self.shift_low()

    def encode_bit(self, probs: list[int], index: int, bit: int) -> None:
        prob = probs[index]
        bound = (self.range >> 8) * prob
        prob -= prob >> 3

        if bit:
            self.range = bound
            probs[index] = prob + 31
        else:
            self.low += bound
            self.range -= bound
            probs[index] = prob

        self.normalize()

    def encode_bittree(self, probs: list[int], offset: int, number: int) -> None:
        for i in range(number.bit_length() - 2, -1, -1):
            self.encode_bit(probs, offset + (number >> (i + 1)), (number >> i) & 1)

    def encode_number(self, probs: list[int], offset: int, bits: int, number: int) -> None:
        if bits > 3:
            self.encode_bit(probs, offset + 3, (number >> (bits - 1)) & 1)
            if bits > 4:
                self.encode_bit(probs, offset + 3, (number >> (bits - 2)) & 1)
                if bits > 5:
                    for i in range(bits - 3, 2, -1):
                        self.range >>= 1
                        if not (number >> i) & 1:
                            self.low += self.range
                    self.normalize()

        count = min(bits, 3)
        for i in range(count):
            self.encode_bit(probs, offset + i, (number >> (count - 1 - i)) & 1)

    def flush(self) -> None:
        for _ in range(5):
            self.shift_low()


def compress(src: bytes | BinaryIO) -> bytes:
    """LZRC compress from a file-like object or bytes.

    Args:
        src: File-like object or bytes to compress.

    Returns:
        The compressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    data = src.read()
    rc = _RangeEncoder()

    bm_literal, bm_dist_bits, bm_dist, bm_match, bm_len = _init_probabilities()

    chains = defaultdict(lambda: deque(maxlen=CHAIN_LIMIT))
    state = 0
    offset = 0

    while offset < len(data):
        length = 0
        distance = 0

        for match_offset in reversed(chains.get(data[offset : offset + MIN_MATCH], ())):
            if offset - match_offset > WINDOW:
                break

            match_length = MIN_MATCH
            while (
                match_length < MAX_MATCH
                and offset + match_length < len(data)
                and data[match_offset + match_length] == data[offset + match_length]
            ):
                match_length += 1

            # Matches of the minimum length can only have a distance of up to 255
            if match_length > length and (match_length > MIN_MATCH or offset - match_offset <= 0xFF):
                length = match_length
                distance = offset - match_offset

        if length == 0:
            # Literal
            rc.encode_bit(bm_match[state], 0, 0)
            if state > 0:
                state -= 1

            last_byte = data[offset - 1] if offset else 0
            rc.encode_bittree(bm_literal[last_byte & 0x07], 0, data[offset] | 0x100)
            length = 1
        else:
            # Match, the decoder copies one byte more than the encoded length
            rc.encode_bit(bm_match[state], 0, 1)

            length_bits = (length - 1).bit_length() - 1
            for step in range(1, length_bits + 1):
                rc.encode_bit(bm_match[state], step, 1)
            if length_bits < 7:
                rc.encode_bit(bm_match[state], length_bits + 1, 0)

            if length_bits > 0:
                length_state = ((length_bits - 1) << 2) + ((offset << (length_bits - 1)) & 0x03)
                rc.encode_number(bm_len[state], length_state, length_bits, length - 1)

            distance_state, limit = (7, 44) if length - 1 > 2 else (0, 8)
            distance_bits = distance.bit_length() - 1
            rc.encode_bittree(bm_dist_bits[length_bits], distance_state, distance_bits + limit)
            rc.encode_number(bm_dist[distance_bits], 0, distance_bits, distance)

            state = 6 + ((offset + length + 1) & 1)

        for i in range(offset, offset + length):
            chains[data[i : i + MIN_MATCH]].append(i)
        offset += length

    # End of stream is a match with the maximum encoded length
    rc.encode_bit(bm_match[state], 0, 1)
    for step in range(1, 8):
        rc.encode_bit(bm_match[state], step, 1)
    rc.encode_number(bm_len[state], 6 << 2, 7, END_OF_STREAM)
    rc.flush()

    # The first byte of the range coder is always 0, which doubles as the literal context
    return bytes(rc.dst)


def decompress(src: bytes | BinaryIO, buflen: int = -1) -> bytes:
    """LZRC decompress from a file-like object or bytes.

    The stream is terminated by an end of stream marker, so ``buflen`` is only needed to limit the output size.

    Args:
        src: File-like object or bytes to decompress.
        buflen: The maximum size of the decompressed data, or ``-1`` to not limit it.

    Returns:
        The decompressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    if len(header := src.read(5)) != 5:
        raise ValueError("Truncated LZRC stream")

    lc = header[0]
    code = int.from_bytes(header[1:], "big")

    if buflen < 0:
        buflen = sys.maxsize

    if lc & 0x80:
        # Not compressed
        return src.read(min(code, buflen))

    rc = _RangeDecoder(src, code)

    bm_literal, bm_dist_bits, bm_dist, bm_match, bm_len = _init_probabilities()

    dst = bytearray()
    state = 0

    while True:
        if rc.decode_bit(bm_match[state], 0) == 0:
            # Literal
            if state > 0:
                state -= 1

            if len(dst) >= buflen:
                raise ValueError("LZRC stream exceeds output buffer")

            last_byte = dst[-1] if dst else 0
            dst.append(rc.decode_bittree(bm_literal[(last_byte >> lc) & 0x07], 0, 0x100) - 0x100)
        else:
            # Match
            length_bits = 0
            for step in range(1, 8):
                if rc.decode_bit(bm_match[state], step) == 0:
                    break
                length_bits += 1

            if length_bits == 0:
                length = 1
            else:
                length_state = ((length_bits - 1) << 2) + ((len(dst) << (length_bits - 1)) & 0x03)
                length = rc.decode_number(bm_len[state], length_state, length_bits)
                if length == END_OF_STREAM:
                    # End of stream
                    break

            distance_state, limit = (7, 44) if length > 2 else (0, 8)
            distance_bits = rc.decode_bittree(bm_dist_bits[length_bits], distance_state, limit) - limit
            distance = rc.decode_number(bm_dist[distance_bits], 0, distance_bits)

            if distance > len(dst):
                raise ValueError("Invalid match distance")

            # The decoder copies one byte more than the encoded length
            length += 1
            if len(dst) + length > buflen:
                raise ValueError("LZRC stream exceeds output buffer")

            if length <= distance:
                dst += dst[-distance : (-distance + length) or None]
            else:
                # The match overlaps the output it produces, so it repeats the last distance bytes
                chunk = dst[-distance:]
                dst += chunk * (length // distance)
                dst += chunk[: length % distance]

            state = 6 + ((len(dst) + 1) & 1)

    return bytes(dst)
