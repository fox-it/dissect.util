from __future__ import annotations

import io

import pytest

from dissect.util import sid


def id_fn(val):
    if isinstance(val, (str,)):
        return val
    else:
        return ""


@pytest.mark.parametrize(
    "binary_sid, readable_sid, endian, swap_last",
    [
        (
            b"\x01\x00\x00\x00\x00\x00\x00\x00",
            "S-1-0",
            "<",
            False,
        ),
        (
            b"\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00",
            "S-1-1-0",
            "<",
            False,
        ),
        (
            b"\x01\x04\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x15\xcd\x5b\x07\x00\x00\x00\x10\xf4\x01\x00\x00",
            "S-1-5-21-123456789-268435456-500",
            "<",
            False,
        ),
        (
            io.BytesIO(b"\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00"),
            "S-1-1-0",
            "<",
            False,
        ),
        (
            b"\x01\x04\x00\x00\x00\x00\x00\x05\x00\x00\x00\x15\x07\x5b\xcd\x15\x10\x00\x00\x00\x00\x00\x01\xf4",
            "S-1-5-21-123456789-268435456-500",
            ">",
            False,
        ),
        (
            b"\x01\x04\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x15\xcd\x5b\x07\x00\x00\x00\x10\x00\x00\x01\xf4",
            "S-1-5-21-123456789-268435456-500",
            "<",
            True,
        ),
        (
            b"\x01\x04\x00\x00\x00\x00\x00\x05\x00\x00\x00\x15\x07\x5b\xcd\x15\x10\x00\x00\x00\xf4\x01\x00\x00",
            "S-1-5-21-123456789-268435456-500",
            ">",
            True,
        ),
    ],
    ids=id_fn,
)
def test_read_sid(binary_sid: bytes | io.BinaryIO, endian: str, swap_last: bool, readable_sid: str) -> None:
    assert readable_sid == sid.read_sid(binary_sid, endian, swap_last)
