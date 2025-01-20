from __future__ import annotations

import struct
import sys
from typing import TYPE_CHECKING, Any, cast, overload

if TYPE_CHECKING:
    from collections.abc import Iterator


def xmemoryview(buf: bytes | bytearray | memoryview, format: str) -> memoryview | _xmemoryview:
    """Cast a memoryview to the specified format, including endianness.

    The regular ``memoryview.cast()`` method only supports host endianness. While that should be fine 99% of the time
    (most of the world runs on little endian systems), we'd rather it be fine 100% of the time. This utility method
    ensures that by transparently converting between endianness if it doesn't match the host endianness.

    If the host endianness matches the requested endianness, this simply returns a regular ``memoryview.cast()``.

    See ``memoryview.cast()`` for more details on what that actually does.

    Args:
        buf: The bytes object or memoryview to cast.
        format: The format to cast to in ``struct`` format syntax.

    Raises:
        ValueError: If the format is invalid.
        TypeError: If the view is of an invalid type.
    """
    if len(format) != 2:
        raise ValueError("Invalid format specification")

    view = memoryview(buf) if isinstance(buf, (bytes, bytearray)) else buf
    if not isinstance(view, memoryview):  # type: ignore
        raise TypeError("view must be a memoryview, bytes or bytearray object")

    endian = format[0]
    view = cast(memoryview, view.cast(format[1]))  # type: ignore

    if (
        endian in ("@", "=")
        or (sys.byteorder == "little" and endian == "<")
        or (sys.byteorder == "big" and endian in (">", "!"))
    ):
        # Native endianness, don't need to do anything
        return view

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
        return self._convert_list(self._view.tolist())

    def _convert(self, value: int) -> int:
        return self._struct_to.unpack(self._struct_frm.pack(value))[0]

    def _convert_list(self, value: list[int]) -> list[int]:
        endian = self._format[0]
        fmt = self._format[1]
        pck = f"{len(value)}{fmt}"
        return list(struct.unpack(f"{endian}{pck}", struct.pack(f"={pck}", *value)))

    @overload
    def __getitem__(self, idx: int) -> int: ...

    @overload
    def __getitem__(self, idx: slice) -> _xmemoryview: ...

    def __getitem__(self, idx: int | slice) -> int | _xmemoryview:
        value = self._view[idx]
        if isinstance(value, int):
            return self._convert(value)
        if isinstance(value, memoryview):  # type: ignore
            return _xmemoryview(value, self._format)

        raise TypeError("Invalid index type")

    def __setitem__(self, *args: Any, **kwargs: Any) -> None:
        # setitem looks like it's a no-op on cast memoryviews?
        pass

    def __len__(self) -> int:
        return len(self._view)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, _xmemoryview):
            other = other._view
        return self._view.__eq__(other)

    def __iter__(self) -> Iterator[int]:
        for value in self._view:
            yield self._convert(value)

    def __getattr__(self, attr: str) -> Any:
        return getattr(self._view, attr)
