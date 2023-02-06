from __future__ import annotations

import struct
import sys
from typing import Any, Iterator, Union


def xmemoryview(view: bytes, format: str) -> Union[memoryview, _xmemoryview]:
    """Cast a memoryview to the specified format, including endianness.

    The regular ``memoryview.cast()`` method only supports host endianness. While that should be fine 99% of the time
    (most of the world runs on little endian systems), we'd rather it be fine 100% of the time. This utility method
    ensures that by transparently converting between endianness if it doesn't match the host endianness.

    If the host endianness matches the requested endianness, this simply returns a regular ``memoryview.cast()``.

    See ``memoryview.cast()`` for more details on what that actually does.

    Args:
        view: The bytes object or memoryview to cast.
        format: The format to cast to in ``struct`` format syntax.

    Raises:
        ValueError: If the format is invalid.
        TypeError: If the view is of an invalid type.
    """
    if len(format) != 2:
        raise ValueError("Invalid format specification")

    if isinstance(view, (bytes, bytearray)):
        view = memoryview(view)

    if not isinstance(view, memoryview):
        raise TypeError("view must be a memoryview, bytes or bytearray object")

    endian = format[0]
    view = view.cast(format[1])

    if (
        endian in ("@", "=")
        or (sys.byteorder == "little" and endian == "<")
        or (sys.byteorder == "big" and endian in (">", "!"))
    ):
        # Native endianness, don't need to do anything
        return view
    else:
        # Non-native endianness
        return _xmemoryview(view, format)


class _xmemoryview:
    """Wrapper for memoryview that converts between host and a different destination endianness.

    Args:
        view: The (already casted) memoryview to wrap.
        format: The format to convert to.
    """

    def __init__(self, view: memoryview, format: str):
        self._format = format

        fmt = format[1]
        self._view = view
        self._struct_frm = struct.Struct(f"={fmt}")
        self._struct_to = struct.Struct(format)

    def tolist(self) -> list[int]:
        return self._convert(self._view.tolist())

    def _convert(self, value: Union[list[int], int]) -> int:
        if isinstance(value, list):
            endian = self._format[0]
            fmt = self._format[1]
            pck = f"{len(value)}{fmt}"
            return list(struct.unpack(f"{endian}{pck}", struct.pack(f"={pck}", *value)))
        return self._struct_to.unpack(self._struct_frm.pack(value))[0]

    def __getitem__(self, idx: Union[int, slice]) -> Union[int, bytes]:
        value = self._view[idx]
        if isinstance(idx, int):
            return self._convert(value)
        if isinstance(idx, slice):
            return _xmemoryview(self._view[idx], self._format)

    def __setitem__(self, *args, **kwargs) -> None:
        # setitem looks like it's a no-op on cast memoryviews?
        pass

    def __len__(self) -> int:
        return len(self._view)

    def __eq__(self, other: Union[memoryview, _xmemoryview]):
        if isinstance(other, _xmemoryview):
            other = other._view
        return self._view.__eq__(other)

    def __iter__(self) -> Iterator[int]:
        for value in self._view:
            yield self._convert(value)

    def __getattr__(self, attr: str) -> Any:
        return getattr(self._view, attr)
