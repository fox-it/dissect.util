# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-frs2/8cb5bae9-edf3-4833-9f0a-9d7e24218d3d
# https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-XCA/[MS-XCA].pdf

import io
import struct
from collections import namedtuple


Symbol = namedtuple("Symbol", ["length", "symbol"])


def read_16_bit(fh):
    return struct.unpack("<H", fh.read(2).rjust(2, b"\x00"))[0]


class Node:
    __slots__ = ("symbol", "is_leaf", "children")

    def __init__(self, symbol=None, is_leaf=False):
        self.symbol = symbol
        self.is_leaf = is_leaf
        self.children = [None, None]


def add_leaf(nodes, idx, mask, bits):
    node = nodes[0]
    i = idx + 1

    while bits > 1:
        bits -= 1
        childidx = (mask >> bits) & 1
        if node.children[childidx] is None:
            node.children[childidx] = nodes[i]
            nodes[i].is_leaf = False
            i += 1
        node = node.children[childidx]

    node.children[mask & 1] = nodes[idx]
    return i


def build_tree(buf):
    if len(buf) != 256:
        raise ValueError("Not enough data for Huffman code tree")

    nodes = [Node() for _ in range(1024)]
    symbols = []

    for i, c in enumerate(buf):
        symbols.append(Symbol(c & 0x0F, i * 2))
        symbols.append(Symbol((c >> 4) & 0x0F, i * 2 + 1))

    symbols = sorted(symbols)

    symbol_index_start = 0
    for s in symbols:
        if s.length > 0:
            break
        symbol_index_start += 1

    mask = 0
    bits = 1

    root = nodes[0]

    tree_index = 1
    for symbol_index in range(symbol_index_start, 512):
        s = symbols[symbol_index]

        node = nodes[tree_index]
        node.symbol = s.symbol
        node.is_leaf = True

        mask = (mask << s.length - bits) & 0xFFFFFFFF
        bits = s.length

        tree_index = add_leaf(nodes, tree_index, mask, bits)
        mask += 1

    return root


class BitString:
    def __init__(self):
        self.source = None
        self.mask = 0
        self.bits = 0

    @property
    def index(self):
        return self.source.tell()

    def init(self, fh):
        self.mask = (read_16_bit(fh) << 16) + read_16_bit(fh)
        self.bits = 32
        self.source = fh

    def read(self, n):
        return self.source.read(n)

    def lookup(self, n):
        if n == 0:
            return 0

        return self.mask >> (32 - n)

    def skip(self, n):
        self.mask = (self.mask << n) & 0xFFFFFFFF
        self.bits -= n
        if self.bits < 16:
            self.mask += read_16_bit(self.source) << (16 - self.bits)
            self.bits += 16

    def decode(self, root):
        node = root
        while not node.is_leaf:
            bit = self.lookup(1)
            self.skip(1)
            node = node.children[bit]
        return node.symbol


def decompress(src):
    """LZXPRESS decompress from a file-like object.

    Decompresses until EOF of the input file-like object.

    Args:
        src: File-like object to decompress from.

    Returns:
        bytearray: The decompressed bytes.
    """
    dst = bytearray()

    start_offset = src.tell()
    src.seek(0, io.SEEK_END)
    size = src.tell() - start_offset
    src.seek(start_offset, io.SEEK_SET)

    bitstring = BitString()

    while src.tell() - start_offset < size:
        root = build_tree(src.read(256))
        bitstring.init(src)

        chunk_size = 0
        while chunk_size < 65536 and src.tell() - start_offset < size:
            symbol = bitstring.decode(root)
            if symbol < 256:
                dst.append(symbol)
                chunk_size += 1
            else:
                symbol -= 256
                length = symbol & 0x0F
                symbol >>= 4

                offset = (1 << symbol) + bitstring.lookup(symbol)

                if length == 15:
                    length = ord(bitstring.read(1)) + 15

                    if length == 270:
                        length = read_16_bit(bitstring.source)

                bitstring.skip(symbol)

                length += 3
                for _ in range(length):
                    dst.append(dst[-offset])
                chunk_size += length

    return io.BytesIO(bytes(dst))
