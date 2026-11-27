"""LZFSE compression and decompression.

LZFSE is an Apple compression that combines LZ77 with finite state entropy coding. APFS can use it for compressed files.
Blocks that are compressed with LZVN are decompressed with :mod:`dissect.util.compression.lzvn`.

References:
    - https://github.com/lzfse/lzfse
"""

from __future__ import annotations

import bisect
import io
import struct
from collections import defaultdict, deque
from typing import BinaryIO, NamedTuple

from dissect.util.compression import lzvn

LZFSE_ENDOFSTREAM_BLOCK_MAGIC = b"bvx$"  # 0x24787662 (end of stream)
LZFSE_UNCOMPRESSED_BLOCK_MAGIC = b"bvx-"  # 0x2d787662 (raw data)
LZFSE_COMPRESSEDV1_BLOCK_MAGIC = b"bvx1"  # 0x31787662 (lzfse compressed, uncompressed tables)
LZFSE_COMPRESSEDV2_BLOCK_MAGIC = b"bvx2"  # 0x32787662 (lzfse compressed, compressed tables)
LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC = b"bvxn"  # 0x6e787662 (lzvn compressed)

# Throughout LZFSE we refer to "L", "M" and "D"; these will always appear as
# a triplet, and represent a "usual" LZ-style literal and match pair.  "L"
# is the number of literal bytes, "M" is the number of match bytes, and "D"
# is the match "distance"; the distance in bytes between the current pointer
# and the start of the match.
LZFSE_ENCODE_L_SYMBOLS = 20
LZFSE_ENCODE_M_SYMBOLS = 20
LZFSE_ENCODE_D_SYMBOLS = 64
LZFSE_ENCODE_LITERAL_SYMBOLS = 256
LZFSE_ENCODE_L_STATES = 64
LZFSE_ENCODE_M_STATES = 64
LZFSE_ENCODE_D_STATES = 256
LZFSE_ENCODE_LITERAL_STATES = 1024
LZFSE_MATCHES_PER_BLOCK = 10000
LZFSE_LITERALS_PER_BLOCK = 4 * LZFSE_MATCHES_PER_BLOCK
LZFSE_ENCODE_MAX_L_VALUE = 315
LZFSE_ENCODE_MAX_M_VALUE = 2359
LZFSE_ENCODE_MAX_D_VALUE = 262139

MIN_MATCH = 4
CHAIN_LIMIT = 128

# fmt: off
_lzfse_freq_nbits_table = (
    2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14,
    2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14
)
_lzfse_freq_value_table = (
    0, 2, 1, 4, 0, 3, 1, -1, 0, 2, 1, 5, 0, 3, 1, -1,
    0, 2, 1, 6, 0, 3, 1, -1, 0, 2, 1, 7, 0, 3, 1, -1
)

# The L, M, D data streams are all encoded as a "base" value, which is
# FSE-encoded, and an "extra bits" value, which is the difference between
# value and base, and is simply represented as a raw bit value (because it
# is the low-order bits of a larger number, not much entropy can be
# extracted from these bits by more complex encoding schemes). The following
# tables represent the number of low-order bits to encode separately and the
# base values for each of L, M, and D.
_l_extra_bits = (
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 5, 8
)
_l_base_value = (
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 28, 60
)
_m_extra_bits = (
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 5, 8, 11
)
_m_base_value = (
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 24, 56, 312
)
_d_extra_bits = (
    0,  0,  0,  0,  1,  1,  1,  1,  2,  2,  2,  2,  3,  3,  3,  3,
    4,  4,  4,  4,  5,  5,  5,  5,  6,  6,  6,  6,  7,  7,  7,  7,
    8,  8,  8,  8,  9,  9,  9,  9,  10, 10, 10, 10, 11, 11, 11, 11,
    12, 12, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15
)
_d_base_value = (
    0,      1,      2,      3,     4,     6,     8,     10,    12,    16,
    20,     24,     28,     36,    44,    52,    60,    76,    92,    108,
    124,    156,    188,    220,   252,   316,   380,   444,   508,   636,
    764,    892,    1020,   1276,  1532,  1788,  2044,  2556,  3068,  3580,
    4092,   5116,   6140,   7164,  8188,  10236, 12284, 14332, 16380, 20476,
    24572,  28668,  32764,  40956, 49148, 57340, 65532, 81916, 98300, 114684,
    131068, 163836, 196604, 229372
)
# fmt: on


_I = struct.Struct("<I")


def _clz(n: int) -> int:
    if n == 0:
        return 32
    return 32 - n.bit_length()


class LZFSECompressedBlockHeader(NamedTuple):
    """LZFSE compressed block header."""

    __struct_v1__ = struct.Struct(
        "<IIIIIIi4HiHHH"
        f"{LZFSE_ENCODE_L_SYMBOLS}H"
        f"{LZFSE_ENCODE_M_SYMBOLS}H"
        f"{LZFSE_ENCODE_D_SYMBOLS}H"
        f"{LZFSE_ENCODE_LITERAL_SYMBOLS}H"
    )
    __struct_v2__ = struct.Struct("<I3Q")

    n_raw_bytes: int
    n_payload_bytes: int
    n_literals: int
    n_matches: int
    n_literal_payload_bytes: int
    n_lmd_payload_bytes: int
    literal_bits: int
    literal_state: tuple[int, int, int, int]
    lmd_bits: int
    l_state: int
    m_state: int
    d_state: int
    l_freq: tuple[int, ...]
    m_freq: tuple[int, ...]
    d_freq: tuple[int, ...]
    literal_freq: tuple[int, ...]

    @classmethod
    def parse_v1(cls, fh: BinaryIO) -> LZFSECompressedBlockHeader:
        """Decode all fields from a v1 header."""
        values = cls.__struct_v1__.unpack(fh.read(cls.__struct_v1__.size))

        return cls(
            n_raw_bytes=values[0],
            n_payload_bytes=values[1],
            n_literals=values[2],
            n_matches=values[3],
            n_literal_payload_bytes=values[4],
            n_lmd_payload_bytes=values[5],
            literal_bits=values[6],
            literal_state=values[7:11],
            lmd_bits=values[11],
            l_state=values[12],
            m_state=values[13],
            d_state=values[14],
            l_freq=values[15 : 15 + LZFSE_ENCODE_L_SYMBOLS],
            m_freq=values[35 : 35 + LZFSE_ENCODE_M_SYMBOLS],
            d_freq=values[55 : 55 + LZFSE_ENCODE_D_SYMBOLS],
            literal_freq=values[119 : 119 + LZFSE_ENCODE_LITERAL_SYMBOLS],
        )

    @classmethod
    def parse_v2(cls, fh: BinaryIO) -> LZFSECompressedBlockHeader:
        """Decode all fields from a v2 header."""
        values = cls.__struct_v2__.unpack(fh.read(cls.__struct_v2__.size))
        v0, v1, v2 = values[1:4]

        n_literal_payload_bytes = _get_field(v0, 20, 20)
        n_lmd_payload_bytes = _get_field(v1, 40, 20)
        n_payload_bytes = n_literal_payload_bytes + n_lmd_payload_bytes

        freq_tables_size = _get_field(v2, 0, 32) - cls.__struct_v2__.size - 4  # exclude magic

        if freq_tables_size == 0:
            l_freq = (0,) * 20
            m_freq = (0,) * 20
            d_freq = (0,) * 64
            literal_freq = (0,) * 256
        else:
            accum = 0
            accum = int.from_bytes(fh.read(freq_tables_size), "little")
            result = [0] * 720

            for i in range(
                LZFSE_ENCODE_L_SYMBOLS + LZFSE_ENCODE_M_SYMBOLS + LZFSE_ENCODE_D_SYMBOLS + LZFSE_ENCODE_LITERAL_SYMBOLS
            ):
                # Decode and store value
                nbits, value = _decode_v1_freq_value(accum)
                result[i] = value

                # Consume nbits bits
                accum >>= nbits

            l_freq = tuple(result[0:20])
            m_freq = tuple(result[20:40])
            d_freq = tuple(result[40:104])
            literal_freq = tuple(result[104:360])

        return cls(
            n_raw_bytes=values[0],
            n_payload_bytes=n_payload_bytes,
            n_literals=_get_field(v0, 0, 20),
            n_matches=_get_field(v0, 40, 20),
            n_literal_payload_bytes=n_literal_payload_bytes,
            n_lmd_payload_bytes=n_lmd_payload_bytes,
            literal_bits=_get_field(v0, 60, 3) - 7,
            literal_state=(
                _get_field(v1, 0, 10),
                _get_field(v1, 10, 10),
                _get_field(v1, 20, 10),
                _get_field(v1, 30, 10),
            ),
            lmd_bits=_get_field(v1, 60, 3) - 7,
            l_state=_get_field(v2, 32, 10),
            m_state=_get_field(v2, 42, 10),
            d_state=_get_field(v2, 52, 10),
            l_freq=l_freq,
            m_freq=m_freq,
            d_freq=d_freq,
            literal_freq=literal_freq,
        )


def _get_field(value: int, offset: int, nbits: int) -> int:
    """Extracts up to 32 bits from a 64-bit field beginning at offset, and zero-extends them to a 32-bit int.

    If we number the bits of ``value`` from 0 (least significant) to 63 (most significant),
    the result is bits ``offset`` to ``offset+nbits-1``.
    """
    return (value >> offset) & ((1 << nbits) - 1)


def _decode_v1_freq_value(bits: int) -> tuple[int, int]:
    """Decode an entry value from next bits of stream."""
    b = bits & 31
    n = _lzfse_freq_nbits_table[b]

    # Special cases for > 5 bits encoding
    if n == 8:
        value = 8 + ((bits >> 4) & 0xF)
    elif n == 14:
        value = 24 + ((bits >> 4) & 0x3FF)
    else:
        value = _lzfse_freq_value_table[b]

    return n, value


class DecoderEntry(NamedTuple):
    """Entry for one state in the decoder table."""

    k: int  # Number of bits to read
    symbol: int  # Emitted symbol
    delta: int  # Signed increment used to compute next state (+bias)


class EncoderEntry(NamedTuple):
    """Entry for one symbol in the encoder table."""

    s0: int  # First state requiring a K-bit shift
    k: int  # States S >= S0 are shifted K bits, states S < S0 are shifted K-1 bits
    delta0: int  # Relative increment used to compute next state if S >= S0
    delta1: int  # Relative increment used to compute next state if S < S0


class ValueDecoderEntry(NamedTuple):
    """Entry for one state in the value decoder table."""

    total_bits: int  # state bits + extra value bits = shift for next decode
    value_bits: int  # extra value bits
    delta: int  # state base (delta)
    vbase: int  # value base


def _init_decoder_table(nstates: int, freq: tuple[int, ...]) -> list[DecoderEntry]:
    """Initialize decoder table ``T[nstates]``.

    ``nstates = sum freq[i]`` is the number of states (a power of 2).
    ``freq`` is a normalized histogram of symbol frequencies, with ``freq[i] >= 0``.

    Some symbols may have a 0 frequency. In that case, they should not be present in the data.
    """
    table = []

    n_clz = _clz(nstates)
    sum_of_freq = 0

    for i, f in enumerate(freq):
        if f == 0:
            # skip this symbol, no occurrences
            continue

        sum_of_freq += f
        if sum_of_freq > nstates:
            raise ValueError("Invalid frequency table")
        k = _clz(f) - n_clz  # shift needed to ensure N <= (F<<K) < 2*N
        j0 = ((2 * nstates) >> k) - f

        # Initialize all states S reached by this symbol: OFFSET <= S < OFFSET + F
        table.extend(
            DecoderEntry(
                k=k if j < j0 else k - 1,
                symbol=i,
                delta=((f + j) << k) - nstates if j < j0 else (j - j0) << (k - 1),
            )
            for j in range(f)
        )

    return table


def _init_value_decoder_table(
    nstates: int, freq: tuple[int, ...], symbol_vbits: tuple[int, ...], symbol_vbase: tuple[int, ...]
) -> list[ValueDecoderEntry]:
    """Initialize value decoder table ``T[nstates]``.

    ``nstates = sum freq[i]`` is the number of states (a power of 2).
    ``freq`` is a normalized histogram of symbol frequencies, with ``freq[i] >= 0``.
    ``symbol_vbits`` and ``symbol_vbase`` are the number of value bits to read and the base value for each symbol.

    Some symbols may have a 0 frequency. In that case, they should not be present in the data.
    """
    table = []

    n_clz = _clz(nstates)
    for i, f in enumerate(freq):
        if f == 0:
            # skip this symbol, no occurrences
            continue

        k = _clz(f) - n_clz  # shift needed to ensure N <= (F<<K) < 2*N
        j0 = ((2 * nstates) >> k) - f

        # Initialize all states S reached by this symbol: OFFSET <= S < OFFSET + F
        table.extend(
            ValueDecoderEntry(
                total_bits=k + symbol_vbits[i] if j < j0 else (k - 1) + symbol_vbits[i],
                value_bits=symbol_vbits[i],
                delta=(((f + j) << k) - nstates) if j < j0 else ((j - j0) << (k - 1)),
                vbase=symbol_vbase[i],
            )
            for j in range(f)
        )

    return table


class _BitStream:
    def __init__(self, data: bytes, nbits: int):
        self.accum = int.from_bytes(data, "little")
        self.nbits = nbits + (len(data) * 8)

    def pull(self, n: int) -> int:
        self.nbits -= n
        result = self.accum >> self.nbits
        self.accum &= (1 << self.nbits) - 1
        return result


class _BitWriter:
    def __init__(self):
        self.dst = bytearray()
        self.buffer = 0
        self.bits = 0

    def push(self, n: int, value: int) -> None:
        self.buffer |= value << self.bits
        self.bits += n

        while self.bits >= 8:
            self.dst.append(self.buffer & 0xFF)
            self.buffer >>= 8
            self.bits -= 8

    def finish(self) -> int:
        """Write the last bits padded with zeros, and return the negative number of padding bits."""
        if not self.bits:
            return 0

        self.dst.append(self.buffer)
        return self.bits - 8


def _init_encoder_table(nstates: int, freq: list[int]) -> list[EncoderEntry | None]:
    """Initialize encoder table ``T[nsymbols]``, with the same parameters as the decoder table.

    Symbols with a 0 frequency don't have an entry, they should not be present in the data.
    """
    table = []
    offset = 0

    for f in freq:
        if f == 0:
            table.append(None)
            continue

        k = nstates.bit_length() - f.bit_length()  # shift needed to ensure N <= (F<<K) < 2*N
        table.append(
            EncoderEntry(
                s0=(f << k) - nstates,
                k=k,
                delta0=offset - f + (nstates >> k),
                delta1=offset - f + ((2 * nstates) >> k),
            )
        )
        offset += f

    return table


def _normalize_freq(nstates: int, counts: list[int]) -> list[int]:
    """Normalize the number of occurrences of each symbol to frequencies that add up to ``nstates``."""
    # Every used symbol gets a state, the other states are divided by the number of occurrences, and the states that are
    # left after rounding down go to the most frequent symbol. Without any occurrences that's the first symbol, like
    # the reference encoder does.
    used = len(counts) - counts.count(0)
    total = sum(counts) or 1
    freq = [1 + count * (nstates - used) // total if count else 0 for count in counts]
    freq[counts.index(max(counts))] += nstates - sum(freq)
    return freq


def _encode_v1_freq_value(value: int) -> tuple[int, int]:
    """Encode an entry value, return the number of bits and the bits."""
    if value < 8:
        b = _lzfse_freq_value_table.index(value)
        return _lzfse_freq_nbits_table[b], b

    if value < 24:
        return 8, 7 + ((value - 8) << 4)

    return 14, 15 + ((value - 24) << 4)


def _encode(state: int, encoder_table: list[EncoderEntry | None], out_stream: _BitWriter, symbol: int) -> int:
    """Encode symbol using the encoder table, and return the updated state."""
    e = encoder_table[symbol]

    # Write the lower K bits of the state, and update the state with the remaining bits and delta
    k, delta = (e.k, e.delta0) if state >= e.s0 else (e.k - 1, e.delta1)
    out_stream.push(k, state & ((1 << k) - 1))
    return delta + (state >> k)


def _decode(state: int, decoder_table: list[DecoderEntry], in_stream: _BitStream) -> tuple[int, int]:
    """Decode and return symbol using the decoder table, and update state."""
    e = decoder_table[state]

    # Update state from K bits of input + DELTA
    state = e.delta + in_stream.pull(e.k)

    # Return the symbol for this state
    return state, e.symbol


def _value_decode(state: int, decoder_table: list[ValueDecoderEntry], in_stream: _BitStream) -> tuple[int, int]:
    """Decode and return value using the decoder table, and update state."""
    entry = decoder_table[state]

    state_and_value_bits = in_stream.pull(entry.total_bits)
    state = entry.delta + (state_and_value_bits >> entry.value_bits)

    return state, entry.vbase + (state_and_value_bits & ((1 << entry.value_bits) - 1))


def _decode_lmd(
    dst: bytearray,
    header: LZFSECompressedBlockHeader,
    literals: list[int],
    l_decoder: list[ValueDecoderEntry],
    m_decoder: list[ValueDecoderEntry],
    d_decoder: list[ValueDecoderEntry],
    in_stream: _BitStream,
) -> None:
    symbols = header.n_matches

    l_state = header.l_state
    m_state = header.m_state
    d_state = header.d_state

    lit = io.BytesIO(bytes(literals))

    L = 0
    M = 0
    D = None

    # Matches can refer back into the output of earlier blocks
    while symbols:
        # Decode the next L, M, D symbol from the input stream
        l_state, L = _value_decode(l_state, l_decoder, in_stream)
        if (lit.tell() + L) >= LZFSE_LITERALS_PER_BLOCK + 64:
            raise ValueError("Literal overflow")

        m_state, M = _value_decode(m_state, m_decoder, in_stream)
        d_state, new_d = _value_decode(d_state, d_decoder, in_stream)
        D = new_d if new_d != 0 else D

        if D is None or len(dst) + L < D:
            raise ValueError("Invalid match distance")

        dst += lit.read(L)

        if M <= D:
            dst += dst[-D : (-D + M) or None]
        else:
            # The match overlaps the output it produces, so it repeats the last D bytes
            chunk = dst[-D:]
            dst += chunk * (M // D)
            dst += chunk[: M % D]

        symbols -= 1


def _put_sequence(sequences: list[tuple[int, int, int]], literal_length: int, match_length: int, distance: int) -> None:
    # Literals that don't fit in one L value are split off into sequences without a match, with the most common D
    while literal_length > LZFSE_ENCODE_MAX_L_VALUE:
        sequences.append((LZFSE_ENCODE_MAX_L_VALUE, 0, 1))
        literal_length -= LZFSE_ENCODE_MAX_L_VALUE
    sequences.append((literal_length, match_length, distance))


def compress(src: bytes | BinaryIO) -> bytes:
    """LZFSE compress from a file-like object or bytes.

    Produces compressed blocks with compressed frequency tables (v2).

    Args:
        src: File-like object or bytes to compress.

    Returns:
        The compressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    data = src.read()
    dst = bytearray()

    # The L, M, D sequences of the whole input, a sequence without a match ends the input
    sequences = []
    chains = defaultdict(lambda: deque(maxlen=CHAIN_LIMIT))
    literal_offset = 0
    offset = 0

    while offset < len(data):
        length = 0
        distance = 0

        for match_offset in reversed(chains.get(data[offset : offset + MIN_MATCH], ())):
            if offset - match_offset > LZFSE_ENCODE_MAX_D_VALUE:
                break

            match_length = MIN_MATCH
            while (
                match_length < LZFSE_ENCODE_MAX_M_VALUE
                and offset + match_length < len(data)
                and data[match_offset + match_length] == data[offset + match_length]
            ):
                match_length += 1

            if match_length > length:
                length = match_length
                distance = offset - match_offset

                # A longer match isn't possible
                if length == LZFSE_ENCODE_MAX_M_VALUE:
                    break

        if length == 0:
            # Literal, which is part of the sequence of the next match
            chains[data[offset : offset + MIN_MATCH]].append(offset)
            offset += 1
            continue

        _put_sequence(sequences, offset - literal_offset, length, distance)

        for i in range(offset, offset + length):
            chains[data[i : i + MIN_MATCH]].append(i)
        offset += length
        literal_offset = offset

    if literal_offset < len(data):
        _put_sequence(sequences, len(data) - literal_offset, 0, 1)

    # Every block has a limited number of sequences and literals
    blocks = []
    n_literals = 0
    for sequence in sequences:
        if (
            not blocks
            or len(blocks[-1]) == LZFSE_MATCHES_PER_BLOCK
            or n_literals + sequence[0] > LZFSE_LITERALS_PER_BLOCK
        ):
            blocks.append([])
            n_literals = 0
        blocks[-1].append(sequence)
        n_literals += sequence[0]

    offset = 0
    for block in blocks:
        literals = bytearray()
        values = []
        d_prev = 0
        for L, M, D in block:
            literals += data[offset : offset + L]
            offset += L + M

            # A D of 0 repeats the previous distance
            values.append((L, M, 0 if d_prev == D else D))
            d_prev = D

        n_raw_bytes = sum(L + M for L, M, _ in values)

        # The literals are encoded as 4 interleaved streams, so add 0x00 literals up to a multiple of 4
        literals += bytes(-len(literals) % 4)

        l_symbols = [bisect.bisect_right(_l_base_value, L) - 1 for L, _, _ in values]
        m_symbols = [bisect.bisect_right(_m_base_value, M) - 1 for _, M, _ in values]
        d_symbols = [bisect.bisect_right(_d_base_value, D) - 1 for _, _, D in values]

        l_freq = _normalize_freq(LZFSE_ENCODE_L_STATES, [l_symbols.count(i) for i in range(LZFSE_ENCODE_L_SYMBOLS)])
        m_freq = _normalize_freq(LZFSE_ENCODE_M_STATES, [m_symbols.count(i) for i in range(LZFSE_ENCODE_M_SYMBOLS)])
        d_freq = _normalize_freq(LZFSE_ENCODE_D_STATES, [d_symbols.count(i) for i in range(LZFSE_ENCODE_D_SYMBOLS)])
        literal_freq = _normalize_freq(
            LZFSE_ENCODE_LITERAL_STATES, [literals.count(i) for i in range(LZFSE_ENCODE_LITERAL_SYMBOLS)]
        )

        freq_stream = _BitWriter()
        for value in l_freq + m_freq + d_freq + literal_freq:
            freq_stream.push(*_encode_v1_freq_value(value))
        freq_stream.finish()

        # Encode starting from the last literal and sequence, so that decoding starts from the first
        literal_encoder = _init_encoder_table(LZFSE_ENCODE_LITERAL_STATES, literal_freq)
        literal_stream = _BitWriter()
        literal_state = [0, 0, 0, 0]
        for i in range(len(literals) - 4, -1, -4):
            for j in (3, 2, 1, 0):
                literal_state[j] = _encode(literal_state[j], literal_encoder, literal_stream, literals[i + j])
        literal_bits = literal_stream.finish()

        l_encoder = _init_encoder_table(LZFSE_ENCODE_L_STATES, l_freq)
        m_encoder = _init_encoder_table(LZFSE_ENCODE_M_STATES, m_freq)
        d_encoder = _init_encoder_table(LZFSE_ENCODE_D_STATES, d_freq)
        lmd_stream = _BitWriter()
        l_state = m_state = d_state = 0
        for i in reversed(range(len(values))):
            # Every value is its symbol and the extra bits from the base value of that symbol
            L, M, D = values[i]
            lmd_stream.push(_d_extra_bits[d_symbols[i]], D - _d_base_value[d_symbols[i]])
            d_state = _encode(d_state, d_encoder, lmd_stream, d_symbols[i])
            lmd_stream.push(_m_extra_bits[m_symbols[i]], M - _m_base_value[m_symbols[i]])
            m_state = _encode(m_state, m_encoder, lmd_stream, m_symbols[i])
            lmd_stream.push(_l_extra_bits[l_symbols[i]], L - _l_base_value[l_symbols[i]])
            l_state = _encode(l_state, l_encoder, lmd_stream, l_symbols[i])
        lmd_bits = lmd_stream.finish()

        # The L, M, D payload starts with 8 bytes of padding, for the reference decoder that reads 8 bytes at a time
        lmd_payload = bytes(8) + lmd_stream.dst

        dst += LZFSE_COMPRESSEDV2_BLOCK_MAGIC
        dst += LZFSECompressedBlockHeader.__struct_v2__.pack(
            n_raw_bytes,
            len(literals) | (len(literal_stream.dst) << 20) | (len(values) << 40) | ((7 + literal_bits) << 60),
            literal_state[0]
            | (literal_state[1] << 10)
            | (literal_state[2] << 20)
            | (literal_state[3] << 30)
            | (len(lmd_payload) << 40)
            | ((7 + lmd_bits) << 60),
            (4 + LZFSECompressedBlockHeader.__struct_v2__.size + len(freq_stream.dst))
            | (l_state << 32)
            | (m_state << 42)
            | (d_state << 52),
        )
        dst += freq_stream.dst
        dst += literal_stream.dst
        dst += lmd_payload

    dst += LZFSE_ENDOFSTREAM_BLOCK_MAGIC

    return bytes(dst)


def decompress(src: bytes | BinaryIO) -> bytes:
    """LZFSE decompress from a file-like object or bytes.

    Decompresses until EOF or EOS of the input data.

    Args:
        src: File-like object or bytes to decompress.

    Returns:
        The decompressed data.
    """
    if not hasattr(src, "read"):
        src = io.BytesIO(src)

    dst = bytearray()

    while True:
        magic = src.read(4)

        if magic == LZFSE_ENDOFSTREAM_BLOCK_MAGIC:
            break

        if magic == LZFSE_UNCOMPRESSED_BLOCK_MAGIC:
            (n_raw_bytes,) = _I.unpack(src.read(4))
            if n_raw_bytes == 0:
                continue

            dst += src.read(n_raw_bytes)

        elif magic in (LZFSE_COMPRESSEDV1_BLOCK_MAGIC, LZFSE_COMPRESSEDV2_BLOCK_MAGIC):
            if magic == LZFSE_COMPRESSEDV1_BLOCK_MAGIC:
                header = LZFSECompressedBlockHeader.parse_v1(src)
            else:
                header = LZFSECompressedBlockHeader.parse_v2(src)

            # Like the reference decoder, a block has room for a limited number of literals and L, M, D values
            if header.n_literals > LZFSE_LITERALS_PER_BLOCK or header.n_matches > LZFSE_MATCHES_PER_BLOCK:
                raise ValueError("Invalid LZFSE block header")

            literal_decoder = _init_decoder_table(LZFSE_ENCODE_LITERAL_STATES, header.literal_freq)
            l_decoder = _init_value_decoder_table(LZFSE_ENCODE_L_STATES, header.l_freq, _l_extra_bits, _l_base_value)
            m_decoder = _init_value_decoder_table(LZFSE_ENCODE_M_STATES, header.m_freq, _m_extra_bits, _m_base_value)
            d_decoder = _init_value_decoder_table(LZFSE_ENCODE_D_STATES, header.d_freq, _d_extra_bits, _d_base_value)

            in_stream = _BitStream(src.read(header.n_literal_payload_bytes), header.literal_bits)

            literals = []
            state0, state1, state2, state3 = header.literal_state
            for _ in range(0, header.n_literals, 4):
                state0, result = _decode(state0, literal_decoder, in_stream)
                literals.append(result)
                state1, result = _decode(state1, literal_decoder, in_stream)
                literals.append(result)
                state2, result = _decode(state2, literal_decoder, in_stream)
                literals.append(result)
                state3, result = _decode(state3, literal_decoder, in_stream)
                literals.append(result)

            in_stream = _BitStream(src.read(header.n_lmd_payload_bytes), header.lmd_bits)
            _decode_lmd(dst, header, literals, l_decoder, m_decoder, d_decoder, in_stream)

        elif magic == LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC:
            (n_raw_bytes,) = _I.unpack(src.read(4))
            (n_payload_bytes,) = _I.unpack(src.read(4))

            dst += lzvn.decompress(src.read(n_payload_bytes))

        else:
            raise ValueError(f"Invalid LZFSE block magic: {magic!r}")

    return bytes(dst)
