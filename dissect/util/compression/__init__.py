"""Compression algorithms.

All algorithms are implemented in pure Python. Some also have a faster native Rust version, which is used
automatically when it's available. To get it, import the module from this package::

    from dissect.util.compression import lz4

    lz4.decompress(data)

Importing from the module itself, e.g. ``from dissect.util.compression.lz4 import decompress``, always gives the
pure Python version.

To choose one explicitly, an algorithm with a native version also has ``<name>_native``, e.g. ``lz4_native``,
which is ``None`` when the native version is unavailable, and ``<name>_python``, which is always available.

Modules that share a name with a package on PyPI, such as ``lz4``, are not a replacement for that package. They only
implement the functions they document.
"""

from __future__ import annotations

from dissect.util.compression import lz4, lzo

lz4_python = lz4
lzo_python = lzo

# This selects between a native Rust version of lz4 and lzo (when available) and our own
# pure-Python implementation.
#
# By doing a:
#  from dissect.util.compression import lz4
# or
#  from dissect.util.compression import lzo
#
# in another project will automatically give you one or the other.
#
# The native Rust version is also available as dissect.util.compression.lz4_native
# and dissect.util.compression.lzo_native (when available) and the pure Python
# version is always available as dissect.util.compression.lz4_python and
# dissect.util.compression.lzo_python.
#
# Note that the pure Python implementation and the Rust implementation are NOT a full replacement
# for the "official" lz4 and lzo Python packages: only the decompress() function is implemented, and compress()
# for lz4.
try:
    from dissect.util import _native

    lz4 = lz4_native = _native.compression.lz4
    lzo = lzo_native = _native.compression.lzo
except (ImportError, AttributeError):
    lz4_native = lzo_native = None

__all__ = [
    "adc",
    "huffman",
    "lz4",
    "lz4_native",
    "lz4_python",
    "lzbitmap",
    "lzfse",
    "lznt1",
    "lzo",
    "lzo_native",
    "lzo_python",
    "lzop",
    "lzrc",
    "lzvn",
    "lzxpress",
    "lzxpress9",
    "lzxpress_huffman",
    "sevenbit",
    "snappy",
    "xz",
]
