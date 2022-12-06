import hashlib

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

    assert (
        hashlib.sha256(
            lzo.decompress(
                bytes.fromhex(
                    "160900a40100400003a83e8e6302003800007104ff4000fc012add00032016dd"
                    "00042016dd00052016dd00062016dd00072016dd00082016dd00092016dd000a"
                    "2016dd000b2016dd000c2016dd000d2016dd000e2016dd000f2016dd00102016"
                    "dd00112016dd00122016dd00132016dd00142016dd00152016dd00162016dd00"
                    "172016dd00182016dd00192016dd001a2016dd001b2016dd001c2016dd001d20"
                    "16dd001e2016dd001f2016dd00202016dd00212016dd00222016dd00232016dd"
                    "00242016dd00252016dd00262016dd00272016dd00282016dd00292016dd002a"
                    "2016dd002b2016dd002c2016dd002d2016dd002e2016dd002f2016dd00302016"
                    "dd00312016dd00322016dd00332016dd00342016dd00352016dd00362016dd00"
                    "372016dd00382016dd00392016dd003a2016dd003b2016dd003c2016dd003d20"
                    "16dd003e2016dd003f2016dd00402016dd00412016dd00422016dd00432016dd"
                    "00442016dd00452016dd00462016dd00472016dd00482016dd00492016dd004a"
                    "2016dd004b2016dd004c2016dd004d2016dd004e2016dd004f2016dd00502016"
                    "dd00512016dd00522016dd00532016dd00542016dd00552016dd00562016dd00"
                    "572016dd00582016dd00592016dd005a2016dd005b2016dd005c2016dd005d20"
                    "16dd005e2016dd005f2016dd00602016dd00612016dd00622016dd00632016dd"
                    "00642016dd0065200adf000800ed27dc006001228d57e32501556c29dc00fd0b"
                    "f55d04662b5c00307d010031dd004f5d06675c0027ce06c03f3b5e02e4022059"
                    "0e00880228dd02115d16682002bc03ff020a00ff8902c75d0669dc0322dc5507"
                    "736d616c6c2d66696c652a9500d455046ad404229455016469722f6f045f3639"
                    "2a9a00eb4209096bd80422b0526804082d776974682d78617474722a1e077543"
                    "080a7c3622cd5d91cd126d9500e0943a110000"
                ),
                False,
                8192,
            )
        ).hexdigest()
        == "a4d6951085717a9698cd814899d11c931db1d4c0f7ddc3b1cba0f582142d4cf4"
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
