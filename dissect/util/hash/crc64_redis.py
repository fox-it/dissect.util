from __future__ import annotations

from dissect.util.hash.crc import Crc64

# CRC-64/REDIS: the Jones polynomial, reflected, init 0, xorout 0
_CRC = Crc64(0xAD93D23594C935A9, init=0, xorout=0, reflected=True)


def update(crc: int, data: bytes) -> int:
    """Update CRC-64/REDIS checksum with data.

    Args:
        crc: The initial value of the checksum.
        data: The data to update the checksum with.
    """
    return _CRC.update(crc, data)


def crc64_redis(data: bytes, value: int = 0) -> int:
    """Calculate CRC-64/REDIS checksum of some data, with an optional initial value.

    This is the CRC used by Redis (e.g. in RDB files and ``DUMP`` payloads). It uses the Jones polynomial
    ``0xAD93D23594C935A9``, reflected, with an init and xorout of 0.

    Args:
        data: The data to calculate the checksum of.
        value: The initial value of the checksum. Default is 0.
    """
    return _CRC.update(value, data)
