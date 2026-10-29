from __future__ import annotations

from dissect.util.hash import crc, crc32c, crc64_redis, crc64c

crc_python = crc
crc32c_python = crc32c
crc64c_python = crc64c
crc64_redis_python = crc64_redis

# This selects between a native Rust version of crc/crc32c/crc64c/crc64_redis (when available) and our own
# pure-Python implementation.
#
# By doing a:
#  from dissect.util.hash import crc
#  from dissect.util.hash import crc32c
#  from dissect.util.hash import crc64c
#  from dissect.util.hash import crc64_redis
#
# in another project will automatically give you one or the other.
#
# The native Rust versions are also available as dissect.util.hash.<name>_native (when available).
# The pure Python versions are always available as dissect.util.hash.<name>_python.
try:
    from dissect.util import _native

    crc = crc_native = _native.hash.crc
    crc32c = crc32c_native = _native.hash.crc32c
    crc64c = crc64c_native = _native.hash.crc64c
    crc64_redis = crc64_redis_native = _native.hash.crc64_redis
except (ImportError, AttributeError):
    crc_native = None
    crc32c_native = None
    crc64c_native = None
    crc64_redis_native = None

# Generic CRC classes, e.g.:
#   Crc32(0x04C11DB7, init=0xFFFFFFFF, xorout=0xFFFFFFFF, reflected=True)  # zlib
#   Crc64(0xAD93D23594C935A9, init=0, xorout=0, reflected=True)  # redis
Crc32 = crc.Crc32
Crc64 = crc.Crc64

__all__ = [
    "Crc32",
    "Crc64",
    "crc",
    "crc32",
    "crc32c",
    "crc32c_native",
    "crc32c_python",
    "crc64_redis",
    "crc64_redis_native",
    "crc64_redis_python",
    "crc64c",
    "crc64c_native",
    "crc64c_python",
    "crc_native",
    "crc_python",
    "jenkins",
]
