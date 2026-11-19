from __future__ import annotations

import math
import struct
from datetime import datetime, timedelta, timezone

_UTC = timezone.utc

_EPOCH_UNIX = datetime(1970, 1, 1, tzinfo=_UTC)
_EPOCH_WINDOWS = datetime(1601, 1, 1, tzinfo=_UTC)
_EPOCH_UUID1 = datetime(1582, 10, 15, tzinfo=_UTC)
_EPOCH_OA = datetime(1899, 12, 30, tzinfo=_UTC)
_EPOCH_COCOA = datetime(2001, 1, 1, tzinfo=_UTC)
_EPOCH_GO = datetime(1, 1, 1, tzinfo=_UTC)

# Timestamps are calculated relatively from the epoch of their format with integers, also for float input
# Parts of a microsecond are rounded down instead of to the nearest microsecond, so a timestamp is never later than
# the actual time (50 ns before midnight stays on the same day) and matches the digits that other tools show
# We don't use platform time functions, so this also works before 1970 on Windows and WASM (Emscripten), and
# timestamps outside the range of datetime raise an OverflowError on every platform
_SECOND = timedelta(seconds=1)
_MILLISECOND = timedelta(milliseconds=1)
_MICROSECOND = timedelta(microseconds=1)


def _floor_float(ts: float, numerator: int) -> int:
    """Return ``ts * numerator`` rounded down, without the rounding error of float multiplication."""
    n, d = ts.as_integer_ratio()
    return n * numerator // d


def now() -> datetime:
    """Return an aware datetime object of the current time in UTC."""
    return datetime.now(_UTC)


def unix_now() -> int:
    """Return a Unix timestamp of the current time."""
    return to_unix(now())


def unix_now_ms() -> int:
    """Return a Unix millisecond timestamp of the current time."""
    return to_unix_ms(now())


def unix_now_us() -> int:
    """Return a Unix microsecond timestamp of the current time."""
    return to_unix_us(now())


def unix_now_ns() -> int:
    """Return a Unix nanosecond timestamp of the current time."""
    return to_unix_ns(now())


def to_unix(dt: datetime) -> int:
    """Converts datetime objects into Unix timestamps.

    This is a convenience method.

    Args:
        dt: The datetime object.

    Returns:
        Unix timestamp from the passed datetime object.
    """
    return int(dt.timestamp())


def to_unix_ms(dt: datetime) -> int:
    """Converts datetime objects into Unix millisecond timestamps.

    This is a convenience method.

    Args:
        dt: The datetime object.

    Returns:
        Unix millisecond timestamp from the passed datetime object.
    """
    return int(dt.timestamp() * 1e3)


def to_unix_us(dt: datetime) -> int:
    """Converts datetime objects into Unix microsecond timestamps.

    This is a convenience method.

    Args:
        dt: The datetime object.

    Returns:
        Unix microsecond timestamp from the passed datetime object.
    """
    return int(dt.timestamp() * 1e6)


def to_unix_ns(dt: datetime) -> int:
    """Converts datetime objects into Unix nanosecond timestamps.

    This is a convenience method.

    Args:
        dt: The datetime object.

    Returns:
        Unix nanosecond timestamp from the passed datetime object.
    """
    return to_unix_us(dt) * 1000


def from_unix(ts: float) -> datetime:
    """Converts Unix timestamps to aware datetime objects in UTC.

    This is a convenience method.

    Args:
        ts: The Unix timestamp.

    Returns:
        Datetime object from the passed timestamp.
    """
    if isinstance(ts, float):
        return _EPOCH_UNIX + _MICROSECOND * _floor_float(ts, 1_000_000)
    return _EPOCH_UNIX + _SECOND * ts


def from_unix_ms(ts: float) -> datetime:
    """Converts Unix timestamps in milliseconds to aware datetime objects in UTC.

    Args:
        ts: The Unix timestamp in milliseconds.

    Returns:
        Datetime object from the passed timestamp.
    """
    if isinstance(ts, float):
        return _EPOCH_UNIX + _MICROSECOND * _floor_float(ts, 1000)
    return _EPOCH_UNIX + _MILLISECOND * ts


def from_unix_us(ts: float) -> datetime:
    """Converts Unix timestamps in microseconds to aware datetime objects in UTC.

    Args:
        ts: The Unix timestamp in microseconds.

    Returns:
        Datetime object from the passed timestamp.
    """
    if isinstance(ts, float):
        return _EPOCH_UNIX + _MICROSECOND * _floor_float(ts, 1)
    return _EPOCH_UNIX + _MICROSECOND * ts


def from_unix_ns(ts: int) -> datetime:
    """Converts Unix timestamps in nanoseconds to aware datetime objects in UTC.

    Args:
        ts: The Unix timestamp in nanoseconds.

    Returns:
        Datetime object from the passed timestamp.
    """
    return _EPOCH_UNIX + _MICROSECOND * (ts // 1000)


def xfstimestamp(seconds: int, nano: int) -> datetime:
    """Converts XFS timestamps to aware datetime objects in UTC.

    Args:
        seconds: The XFS timestamp seconds component
        nano: The XFS timestamp nano seconds component
    Returns:
        Datetime object from the passed timestamp.
    """
    return _EPOCH_UNIX + _MICROSECOND * (nano // 1000 + seconds * 1_000_000)


ufstimestamp = xfstimestamp


def wintimestamp(ts: int | tuple[int, int]) -> datetime:
    """Converts Windows ``FILETIME`` timestamps to aware datetime objects in UTC.

    Args:
        ts: The Windows timestamp integer or a tuple of integers (``dwLowDateTime``, ``dwHighDateTime``)

    Returns:
        Datetime object from the passed timestamp.

    Resources:
        - https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime
    """
    if isinstance(ts, tuple):
        if len(ts) != 2:
            raise ValueError(f"Expected (dwLowDateTime, dwHighDateTime) tuple but got {ts!r}")
        ts = (ts[1] << 32) + ts[0]

    return _EPOCH_WINDOWS + _MICROSECOND * (ts // 10)


def oatimestamp(ts: float) -> datetime:
    """Converts OLE Automation timestamps to aware datetime objects in UTC.

    The integer part counts days from 1899-12-30, and the fractional part is the time of day. Before 1899-12-30
    the time of day still counts forward, so -1.25 is 1899-12-29 06:00.

    Args:
        ts: The OLE Automation timestamp.

    Returns:
        Datetime object from the passed timestamp.

    Resources:
        - https://github.com/dotnet/runtime/blob/main/src/libraries/System.Private.CoreLib/src/System/DateTime.cs
    """
    if not isinstance(ts, float):
        # Convert from int to float
        (ts,) = struct.unpack("<d", struct.pack("<Q", ts & 0xFFFFFFFFFFFFFFFF))

    if ts < 0.0:
        # Count the time of day forward from the start of the day: -1.25 becomes -0.75. The subtraction is exact
        fraction, days = math.modf(ts)
        ts = days - fraction

    return _EPOCH_OA + _MICROSECOND * _floor_float(ts, 86_400_000_000)


def webkittimestamp(ts: int) -> datetime:
    """Converts WebKit timestamps to aware datetime objects in UTC.

    Args:
        ts: The WebKit timestamp.

    Returns:
        Datetime object from the passed timestamp.
    """
    return _EPOCH_WINDOWS + _MICROSECOND * ts


def cocoatimestamp(ts: float) -> datetime:
    """Converts Apple Cocoa Core Data timestamps to aware datetime objects in UTC.

    Args:
        ts: The Apple Cocoa Core Data timestamp.

    Returns:
        Datetime object from the passed timestamp.
    """
    if isinstance(ts, float):
        return _EPOCH_COCOA + _MICROSECOND * _floor_float(ts, 1_000_000)
    return _EPOCH_COCOA + _SECOND * ts


def uuid1timestamp(ts: int) -> datetime:
    """Converts UUID version 1 timestamps to aware datetime objects in UTC.

    UUID v1 timestamps have an epoch of 1582-10-15 00:00:00.

    Args:
        ts: The UUID version 1 timestamp

    Returns:
        Datetime object from the passed timestamp.
    """
    return _EPOCH_UUID1 + _MICROSECOND * (ts // 10)


DOS_EPOCH_YEAR = 1980


def dostimestamp(ts: int, centiseconds: int = 0, swap: bool = False) -> datetime:
    """Converts MS-DOS timestamps to naive datetime objects.

    MS-DOS timestamps are recorded in local time, so we leave it up to the caller to add optional timezone information.

    References:
        - https://web.archive.org/web/20180311003959/http://www.vsft.com/hal/dostime.htm

    Args:
        ts: MS-DOS timestamp
        centiseconds: Optional ExFAT centisecond offset. Yes centisecond...
        swap: Optional swap flag if date and time bytes are swapped.

    Returns:
        Datetime object from the passed timestamp.
    """
    # MS-DOS Date Time Format is actually 2 UINT16_T's first 16 bits are the time, second 16 bits are date
    # the year is an offset of the MS-DOS epoch year, which is 1980

    if swap:
        year = ((ts >> 9) & 0x7F) + DOS_EPOCH_YEAR
        month = (ts >> 5) & 0x0F
        day = ts & 0x1F

        hours = (ts >> 27) & 0x1F
        minutes = (ts >> 21) & 0x3F
        seconds = ((ts >> 16) & 0x1F) * 2
    else:  # non-swapped way
        year = ((ts >> 25) & 0x7F) + DOS_EPOCH_YEAR
        month = (ts >> 21) & 0x0F
        day = (ts >> 16) & 0x1F

        hours = (ts >> 11) & 0x1F
        minutes = (ts >> 5) & 0x3F
        seconds = (ts & 0x1F) * 2

    # Note that according to the standard, centiseconds can be at most 199, so
    # extra_seconds will be at most 1.
    extra_seconds, centiseconds = divmod(centiseconds, 100)
    microseconds = centiseconds * 10000

    return datetime(  # noqa: DTZ001
        year,
        month or 1,
        day or 1,
        hours,
        minutes,
        seconds + extra_seconds,
        microseconds,
    )


_GOTIME = struct.Struct(">BQIh")
# Version 2 is used for zone offsets that are not whole minutes, such as local mean time (LMT)
_GOTIME_V2 = struct.Struct(">BQIhb")


def golangtimestamp(raw: bytes) -> datetime:
    """Unmarshal golang ``time.Time`` bytes to a :class:`datetime` object.

    .. code-block::

        struct datetime {
            uint8       version;        // 1 or 2
            uint64      seconds;        // since 01-01-0001 (Gregorian)
            uint32      nanoseconds;
            int16       timezone;       // offset in minutes or -1 if UTC
            int8        timezone_sec;   // seconds part of the offset, only in version 2
        };

    References:
        - https://pkg.go.dev/time
        - https://github.com/golang/go/blob/master/src/time/time.go
    """
    version = raw[:1]
    if version not in (b"\x01", b"\x02"):
        raise ValueError(f"Expected version 1 or 2 but got {version!r}")

    v2 = version == b"\x02"
    size = _GOTIME_V2.size if v2 else _GOTIME.size
    if len(raw) != size:
        raise ValueError(f"Expected {size} bytes but got {len(raw)}")

    if v2:
        _version, seconds, nanoseconds, offset, offset_seconds = _GOTIME_V2.unpack(raw)
    else:
        _version, seconds, nanoseconds, offset = _GOTIME.unpack(raw)
        offset_seconds = 0

    if nanoseconds >= 1_000_000_000:
        raise ValueError(f"Expected nanoseconds below 1000000000 but got {nanoseconds}")

    dt = _EPOCH_GO + _MICROSECOND * (seconds * 1_000_000 + nanoseconds // 1000)
    if offset == -1:
        return dt
    return dt.astimezone(timezone(timedelta(minutes=offset, seconds=offset_seconds)))
