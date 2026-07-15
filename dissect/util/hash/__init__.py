"""Hash utilities providing CRC-32, CRC-32C, CRC-64/NVME, and Jenkins lookup8.

Selects between a native Rust CRC-32C implementation (when available via
dissect.util._native) and a pure-Python fallback. The native version is
exposed as ``crc32c_native`` and the Python version as ``crc32c_python``;
importing ``crc32c`` gives whichever is available, preferring native.
"""

from __future__ import annotations

from dissect.util.hash import crc32c
from dissect.util.hash.crc64 import crc64

crc32c_python = crc32c

# This selects between a native Rust version of crc32c (when available) and our own
# pure-Python implementation.
#
# By doing a:
#  from dissect.util.hash import crc32c
#
# in another project will automatically give you one or the other.
#
# The native Rust version is also available as dissect.util.hash.crc32c_native (when available)
# and the pure Python version is always available as dissect.util.hash.crc32c_python.
try:
    from dissect.util import _native

    crc32c = crc32c_native = _native.hash.crc32c
except (ImportError, AttributeError):
    crc32c_native = None

__all__ = [
    "crc32",
    "crc32c",
    "crc32c_native",
    "crc32c_python",
    "crc64",
    "jenkins",
]
