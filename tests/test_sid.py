from __future__ import annotations

import io
from typing import BinaryIO

import pytest

from dissect.util import sid


def id_fn(val: bytes | str) -> str:
    print(val)
    if isinstance(val, io.BytesIO):
        val = val.getvalue()

    if isinstance(val, str):
        return val

    if isinstance(val, bytes):
        return val.hex()

    return ""


@pytest.mark.parametrize(
    ("binary_sid", "readable_sid"),
    [
        (b"\x01\x00\x00\x00\x00\x00\x00\x00", "S-1-0"),
        (b"\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00", "S-1-1-0"),
        (
            b"\x01\x04\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x15\xcd\x5b\x07\x00\x00\x00\x10\xf4\x01\x00\x00",
            "S-1-5-21-123456789-268435456-500",
        ),
        (io.BytesIO(b"\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00"), "S-1-1-0"),
    ],
    ids=id_fn,
)
def test_read_sid(binary_sid: bytes | BinaryIO, readable_sid: str) -> None:
    assert readable_sid == sid.read_sid(binary_sid)
