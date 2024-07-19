from dissect.util.compression import lz4 as lz4_python
from dissect.util.compression import lzo as lzo_python

# This selects between the native version of lz4 (when installed) and our own
# pure-Python implementation.
#
# By doing a:
#  from dissect.util.compression import lz4
#
# in another project will automatically give you one or the other.
#
# The native version is also available as dissect.util.compression.lz4_native
# (when installed) and the pure Python version is always available as
# dissect.util.compression.lz4_python.
#
# Note that the pure Python implementation is not a full replacement of the
# native lz4 Python package: only the decompress() function is implemented.
try:
    import lz4.block as lz4
    import lz4.block as lz4_native
except ImportError:
    lz4 = lz4_python
    lz4_native = None

# This selects between the native version of lzo (when installed) and our own
# pure-Python implementation.
#
# By doing a:
#  from dissect.util.compression import lzo
#
# in another project will automatically give you one or the other.
#
# The native version is also available as dissect.util.compression.lzo_native
# (when installed) and the pure Python version is always available as
# dissect.util.compression.lzo_python.
#
# Note that the pure Python implementation is not a full replacement of the
# native lzo Python package: only the decompress() function is implemented.
try:
    import lzo
    import lzo as lzo_native
except ImportError:
    lzo = lzo_python
    lzo_native = None

__all__ = [
    "lz4",
    "lz4_native",
    "lz4_python",
    "lznt1",
    "lzo",
    "lzo_native",
    "lzo_python",
    "lzxpress",
    "lzxpress_huffman",
    "sevenbit",
]
