from dissect.util.compression import (
    lz4,
    lznt1,
    lzo,
    lzxpress,
    lzxpress_huffman,
    sevenbit,
)


def test_lz4_decompress():
    assert (
        lz4.decompress(b"\xff\x0cLZ4 compression test string\x1b\x00\xdbPtring") == b"LZ4 compression test string" * 10
    )


def test_lznt1_decompress():
    assert lznt1.decompress(
        bytes.fromhex(
            "38b08846232000204720410010a24701a045204400084501507900c045200524"
            "138805b4024a44ef0358028c091601484500be009e000401189000"
        )
    ) == (
        b"F# F# G A A G F# E D D E F# F# E E F# F# G A A "
        b"G F# E D D E F# E D D E E F# D E F# G F# D E F# "
        b"G F# E D E A F# F# G A A G F# E D D E F# E D D\x00"
    )


def test_lzo_decompress():
    assert (
        lzo.decompress(bytes.fromhex("0361626361626320f314000f616263616263616263616263616263616263110000"), False)
        == b"abc" * 100
    )


def test_lzxpress_huffman_decompress():
    assert (
        lzxpress_huffman.decompress(
            bytes.fromhex(
                "0000000000000000000000000000000000000000000000000000000000000000"
                "0000000000000000000000000000000030230000000000000000000000000000"
                "0000000000000000000000000000000000000000000000000000000000000000"
                "0000000000000000000000000000000000000000000000000000000000000000"
                "0200000000000000000000000000002000000000000000000000000000000000"
                "0000000000000000000000000000000000000000000000000000000000000000"
                "0000000000000000000000000000000000000000000000000000000000000000"
                "0000000000000000000000000000000000000000000000000000000000000000"
                "a8dc0000ff2601"
            )
        )
        == b"abc" * 100
    )


def test_lzxpress_decompress():
    assert lzxpress.decompress(bytes.fromhex("ffff ff1f 6162 6317 000f ff26 01")) == b"abc" * 100


def test_sevenbit_compress():
    result = sevenbit.compress(b"7-bit compression test string")
    target = bytes.fromhex("b796384d078ddf6db8bc3c9fa7df6e10bd3ca783e67479da7d06")
    assert result == target


def test_sevenbit_decompress():
    result = sevenbit.decompress(bytes.fromhex("b796384d078ddf6db8bc3c9fa7df6e10bd3ca783e67479da7d06"))
    target = b"7-bit compression test string"
    assert result == target


def test_sevenbit_decompress_wide():
    result = sevenbit.decompress(bytes.fromhex("b796384d078ddf6db8bc3c9fa7df6e10bd3ca783e67479da7d06"), wide=True)
    target = "7-bit compression test string".encode("utf-16-le")
    assert result == target
