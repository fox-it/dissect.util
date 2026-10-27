from __future__ import annotations

from dissect.util.hash import crc32c, crc64c

crc32c_python = crc32c
crc64c_python = crc64c

# This selects between a native Rust version of crc32c/crc64c (when available) and our own
# pure-Python implementation.
#
# By doing a:
#  from dissect.util.hash import crc32c
#  from dissect.util.hash import crc64c
#
# in another project will automatically give you one or the other.
#
# The native Rust versions are also available as dissect.util.hash.crc32c_native and
# dissect.util.hash.crc64c_native (when available). The pure Python versions are always
# available as dissect.util.hash.crc32c_python and dissect.util.hash.crc64c_python.
try:
    from dissect.util import _native

    crc32c = crc32c_native = _native.hash.crc32c
    crc64c = crc64c_native = _native.hash.crc64c
except (ImportError, AttributeError):
    crc32c_native = None
    crc64c_native = None

__all__ = [
    "crc32",
    "crc32c",
    "crc32c_native",
    "crc32c_python",
    "crc64c",
    "crc64c_native",
    "crc64c_python",
    "jenkins",
]
