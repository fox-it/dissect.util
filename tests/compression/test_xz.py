from __future__ import annotations

import lzma
from io import BytesIO

import pytest

from dissect.util.compression import xz


def test_xz_repair_checksum() -> None:
    buf = BytesIO(
        bytes.fromhex(
            "fd377a585a000004deadbeef0200210116000000deadbeefe00fff001e5d003a"
            "194ace2b0f238ce989a29cfeb182a4e814985366b771770233ca314836000000"
            "2972e8fd62b18ee300013a8020000000deadbeefdeadbeef020000000004595a"
        )
    )

    with pytest.raises(lzma.LZMAError, match="Corrupt input data"):
        lzma.decompress(buf.getvalue())

    repaired = xz.repair_checksum(buf)
    assert lzma.decompress(repaired.read()) == b"test" * 1024
