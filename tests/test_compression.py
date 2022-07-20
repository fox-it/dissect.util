from dissect.util.compression import lzxpress, sevenbit


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
