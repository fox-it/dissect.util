import io

import pytest

from dissect.util import sid

testdata = [
    (b"\x01\x00\x00\x00\x00\x00\x00\x00", "S-1-0"),
    (b"\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00", "S-1-1-0"),
    (
        b"\x01\x04\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x15\xcd\x5b\x07\x00\x00\x00\x10\xf4\x01\x00\x00",
        "S-1-5-21-123456789-268435456-500",
    ),
    (io.BytesIO(b"\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00"), "S-1-1-0"),
]


def id_fn(val):
    if isinstance(val, (str,)):
        return val
    else:
        return ""


@pytest.mark.parametrize("binary_sid, readable_sid", testdata, ids=id_fn)
def test_read_sid(binary_sid, readable_sid):
    assert readable_sid == sid.read_sid(binary_sid)
