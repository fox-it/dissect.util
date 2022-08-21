from __future__ import annotations

import sys
import struct
from typing import Any, Iterator, Union


def xmemoryview(view: bytes, format: str) -> Union[memoryview, _xmemoryview]:
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
        def it(xview):
            for value in xview._view:
                yield xview._convert(value)

        return it(self)

    def __getattr__(self, attr: str) -> Any:
        return getattr(self._view, attr)
