import struct
from datetime import datetime, timedelta, timezone, tzinfo
from platform import system
from typing import Dict


if system().lower() in ("windows", "emscripten"):
    _EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

    def _calculate_timestamp(ts: float) -> datetime:
        """Calculate timestamps relative from Unix epoch.

        Python on Windows and WASM (Emscripten) have problems calculating timestamps before 1970 (Unix epoch).
        Calculating relatively from the epoch is required to correctly calculate those timestamps.
        This method is slower, so we split the implementation between Windows, WASM and other platforms.
        """
        return _EPOCH + timedelta(seconds=ts)

else:

    def _calculate_timestamp(ts: float) -> datetime:
        """Calculate timestamps normally."""
        return datetime.fromtimestamp(ts, tz=timezone.utc)


def now() -> datetime:
    """Return an aware datetime object of the current time in UTC."""
    return datetime.now(timezone.utc)


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
    return _calculate_timestamp(ts)


def from_unix_ms(ts: float) -> datetime:
    """Converts Unix timestamps in milliseconds to aware datetime objects in UTC.

    Args:
        ts: The Unix timestamp in milliseconds.

    Returns:
        Datetime object from the passed timestamp.
    """
    return from_unix(float(ts) * 1e-3)


def from_unix_us(ts: float) -> datetime:
    """Converts Unix timestamps in microseconds to aware datetime objects in UTC.

    Args:
        ts: The Unix timestamp in microseconds.

    Returns:
        Datetime object from the passed timestamp.
    """
    return from_unix(float(ts) * 1e-6)


def from_unix_ns(ts: float) -> datetime:
    """Converts Unix timestamps in nanoseconds to aware datetime objects in UTC.

    Args:
        ts: The Unix timestamp in nanoseconds.

    Returns:
        Datetime object from the passed timestamp.
    """
    return from_unix(float(ts) * 1e-9)


def xfstimestamp(seconds: int, nano: int) -> datetime:
    """Converts XFS timestamps to aware datetime objects in UTC.

    Args:
        seconds: The XFS timestamp seconds component
        nano: The XFS timestamp nano seconds component
    Returns:
        Datetime object from the passed timestamp.
    """
    return _calculate_timestamp(float(seconds) + (1e-9 * nano))


ufstimestamp = xfstimestamp


def wintimestamp(ts: int) -> datetime:
    """Converts Windows timestamps to aware datetime objects in UTC.

    Args:
        ts: The Windows timestamp.

    Returns:
        Datetime object from the passed timestamp.
    """
    return _calculate_timestamp(float(ts) * 1e-7 - 11644473600)  # Thanks FireEye


def oatimestamp(ts: float) -> datetime:
    """Converts OLE Automation timestamps to aware datetime objects in UTC.

    Args:
        ts: The OLE Automation timestamp.

    Returns:
        Datetime object from the passed timestamp.
    """
    if not isinstance(ts, float):
        # Convert from int to float
        (ts,) = struct.unpack("<d", struct.pack("<Q", ts))
    return _calculate_timestamp((ts - 25569) * 86400)


def webkittimestamp(ts: int) -> datetime:
    """Converts WebKit timestamps to aware datetime objects in UTC.

    Args:
        ts: The WebKit timestamp.

    Returns:
        Datetime object from the passed timestamp.
    """
    return _calculate_timestamp(float(ts) * 1e-6 - 11644473600)


def cocoatimestamp(ts: int) -> datetime:
    """Converts Apple Cocoa Core Data timestamps to aware datetime objects in UTC.

    Args:
        ts: The Apple Cocoa Core Data timestamp.

    Returns:
        Datetime object from the passed timestamp.
    """
    return _calculate_timestamp(float(ts) + 978307200)


def dostimestamp(ts: int, centiseconds: int = 0, swap: bool = False) -> datetime:
    """Converts MS-DOS timestamps to naive datetime objects.

    MS-DOS timestamps are recorded in local time, so we leave it up to the
    caller to add optional timezone information.

    According to http://www.vsft.com/hal/dostime.htm

    Args:
        timestap: MS-DOS timestamp
        centisecond: Optional ExFAT centisecond offset. Yes centisecond...
        swap: Optional swap flag if date and time bytes are swapped.

    Returns:
        Datetime object from the passed timestamp.
    """
    DOS_EPOCH_YEAR = 1980

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
    timestamp = datetime(year, month, day, hours, minutes, seconds + extra_seconds, microseconds)

    return timestamp


class UTC(tzinfo):
    """tzinfo class for timezones that have a fixed-offset from UTC

    Args:
        tz_dict: Dictionary of ``{"name": "timezone name", "offset": offset_from_UTC_in_minutes}``
    """

    def __init__(self, tz_dict: Dict[str, int]):
        # offset should be in minutes
        self.name = tz_dict["name"]
        self.offset = timedelta(minutes=tz_dict["offset"])

    def utcoffset(self, dt):
        return self.offset

    def tzname(self, dt):
        return self.name

    def dst(self, dt):
        # do not account for daylight saving
        return timedelta(0)
