from __future__ import annotations

import io
from typing import BinaryIO

import pytest

from dissect.util import sid


def id_fn(val: bytes | str) -> str:
    if isinstance(val, io.BytesIO):
        val = val.getvalue()

    if isinstance(val, str):
        return val

    if val == b"":
        return "empty-value"

    if isinstance(val, bytes):
        return val.hex()

    if val is None:
        return "None"

    return ""


@pytest.mark.parametrize(
    ("binary_sid", "readable_sid", "endian", "swap_last"),
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
        (
            b"",
            "",
            "<",
            False,
        ),
    ],
    ids=id_fn,
)
def test_read_sid(binary_sid: bytes | BinaryIO, endian: str, swap_last: bool, readable_sid: str) -> None:
    assert readable_sid == sid.read_sid(binary_sid, endian, swap_last)
