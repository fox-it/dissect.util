from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import pytest

from dissect.util import ts

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture


def test_now() -> None:
    ts_now = ts.now()
    datetime_now = datetime.now(timezone.utc)
    time_diff = datetime_now - ts_now

    # Should be no difference, so only set microseconds equal to remove processing time difference
    assert timedelta(microseconds=time_diff.microseconds) == time_diff
    assert ts_now.tzinfo == timezone.utc


def test_unix_now() -> None:
    timestamp = ts.unix_now()

    assert isinstance(timestamp, int)
    assert datetime.fromtimestamp(timestamp, tz=timezone.utc).microsecond == 0


def test_unix_now_ms() -> None:
    timestamp = ts.unix_now_ms()

    assert isinstance(timestamp, int)
    assert ts.from_unix_ms(timestamp).microsecond == (timestamp % 1e3) * 1000


def test_unix_now_us() -> None:
    timestamp = ts.unix_now_us()

    assert isinstance(timestamp, int)
    assert ts.from_unix_us(timestamp).microsecond == timestamp % 1e6


def test_unix_now_ns() -> None:
    timestamp = ts.unix_now_ns()

    assert isinstance(timestamp, int)
    assert ts.from_unix_ns(timestamp).microsecond == int((timestamp // 1000) % 1e6)


def test_to_unix() -> None:
    dt = datetime(2018, 4, 11, 23, 34, 32, 915138, tzinfo=timezone.utc)
    assert ts.to_unix(dt) == 1523489672


def test_to_unix_ms() -> None:
    dt = datetime(2018, 4, 11, 23, 34, 32, 915000, tzinfo=timezone.utc)
    assert ts.to_unix_ms(dt) == 1523489672915


def test_to_unix_us() -> None:
    dt = datetime(2018, 4, 11, 23, 34, 32, 915138, tzinfo=timezone.utc)
    assert ts.to_unix_us(dt) == 1523489672915138


def test_to_unix_ns() -> None:
    dt = datetime(2018, 4, 11, 23, 34, 32, 915138, tzinfo=timezone.utc)
    assert ts.to_unix_ns(dt) == 1523489672915138000


def test_from_unix() -> None:
    assert ts.from_unix(1523489672) == datetime(2018, 4, 11, 23, 34, 32, tzinfo=timezone.utc)
    # Parts of a microsecond are rounded down, also before the epoch
    assert ts.from_unix(0.9999999) == datetime(1970, 1, 1, 0, 0, 0, 999999, tzinfo=timezone.utc)
    assert ts.from_unix(-5e-07) == datetime(1969, 12, 31, 23, 59, 59, 999999, tzinfo=timezone.utc)


def test_from_unix_ms() -> None:
    assert ts.from_unix_ms(1511260448882) == datetime(2017, 11, 21, 10, 34, 8, 882000, tzinfo=timezone.utc)
    assert ts.from_unix_ms(0.0015) == datetime(1970, 1, 1, 0, 0, 0, 1, tzinfo=timezone.utc)


def test_from_unix_us() -> None:
    assert ts.from_unix_us(1511260448882000) == datetime(2017, 11, 21, 10, 34, 8, 882000, tzinfo=timezone.utc)
    assert ts.from_unix_us(1.5) == datetime(1970, 1, 1, 0, 0, 0, 1, tzinfo=timezone.utc)
    assert ts.from_unix_us(-0.5) == datetime(1969, 12, 31, 23, 59, 59, 999999, tzinfo=timezone.utc)


def test_from_unix_ns() -> None:
    assert ts.from_unix_ns(1523489672915138048) == datetime(2018, 4, 11, 23, 34, 32, 915138, tzinfo=timezone.utc)
    # Nanoseconds are rounded down to whole microseconds, also before the epoch
    assert ts.from_unix_ns(1523489672915138999) == datetime(2018, 4, 11, 23, 34, 32, 915138, tzinfo=timezone.utc)
    assert ts.from_unix_ns(-1500) == datetime(1969, 12, 31, 23, 59, 59, 999998, tzinfo=timezone.utc)


def test_xfstimestamp() -> None:
    assert ts.xfstimestamp(1582541380, 451742903) == datetime(2020, 2, 24, 10, 49, 40, 451742, tzinfo=timezone.utc)
    assert ts.xfstimestamp(-1, 999998500) == datetime(1969, 12, 31, 23, 59, 59, 999998, tzinfo=timezone.utc)


def test_ufstimestamp() -> None:
    assert ts.ufstimestamp(1582541380, 451742903) == datetime(2020, 2, 24, 10, 49, 40, 451742, tzinfo=timezone.utc)


def test_wintimestamp() -> None:
    assert ts.wintimestamp(131679632729151386) == datetime(2018, 4, 11, 23, 34, 32, 915138, tzinfo=timezone.utc)
    assert ts.wintimestamp(131679632729151380) == datetime(2018, 4, 11, 23, 34, 32, 915138, tzinfo=timezone.utc)
    # 50 nanoseconds before midnight stays on the same day
    assert ts.wintimestamp(131907743999999995) == datetime(2018, 12, 31, 23, 59, 59, 999999, tzinfo=timezone.utc)
    assert ts.wintimestamp((-3804928, 31071617)) == datetime(2023, 11, 22, 20, 18, 4, 503270, tzinfo=timezone.utc)
    assert ts.wintimestamp((0xBACA7E00, 0x01DBD5F8)) == datetime(2025, 6, 5, 9, 3, 40, 0, tzinfo=timezone.utc)

    with pytest.raises(ValueError, match=r"Expected \(dwLowDateTime, dwHighDateTime\) tuple but got \(1234567,\)"):
        ts.wintimestamp((1234567,))


def test_oatimestamp() -> None:
    dt = datetime(2016, 10, 17, 4, 6, 38, 362003, tzinfo=timezone.utc)
    assert ts.oatimestamp(42660.171277338) == dt
    assert ts.oatimestamp(4676095982878497960) == dt
    assert ts.oatimestamp(-4542644417712532139) == datetime(1661, 4, 18, 12, 29, 59, 999999, tzinfo=timezone.utc)
    assert ts.oatimestamp(45028.563718261) == datetime(2023, 4, 12, 13, 31, 45, 257750, tzinfo=timezone.utc)
    assert ts.oatimestamp(2958465.99999) == datetime(9999, 12, 31, 23, 59, 59, 135993, tzinfo=timezone.utc)
    assert ts.oatimestamp(0.99999999999) == datetime(1899, 12, 30, 23, 59, 59, 999999, tzinfo=timezone.utc)


def test_webkittimestamp() -> None:
    assert ts.webkittimestamp(13261574439236538) == datetime(2021, 3, 30, 10, 40, 39, 236538, tzinfo=timezone.utc)
    assert ts.webkittimestamp(13261574439236537) == datetime(2021, 3, 30, 10, 40, 39, 236537, tzinfo=timezone.utc)


def test_uuid1timestamp() -> None:
    """Test if we can convert UUID version 1 timestamps, which count 100 nanoseconds since 1582-10-15."""
    assert ts.uuid1timestamp(137427824729151380) == datetime(2018, 4, 11, 23, 34, 32, 915138, tzinfo=timezone.utc)
    assert ts.uuid1timestamp(137427824729151389) == datetime(2018, 4, 11, 23, 34, 32, 915138, tzinfo=timezone.utc)


def test_cocoatimestamp() -> None:
    assert ts.cocoatimestamp(622894123) == datetime(2020, 9, 27, 10, 8, 43, tzinfo=timezone.utc)
    assert ts.cocoatimestamp(622894123.221783) == datetime(2020, 9, 27, 10, 8, 43, 221783, tzinfo=timezone.utc)
    assert ts.cocoatimestamp(-863538.4521575497) == datetime(2000, 12, 22, 0, 7, 41, 547842, tzinfo=timezone.utc)
    assert ts.cocoatimestamp(622894123.9999999) == datetime(2020, 9, 27, 10, 8, 43, 999999, tzinfo=timezone.utc)


def test_dostimestamp() -> None:
    assert ts.dostimestamp(1391424892, 3) == datetime(2021, 7, 15, 14, 43, 56, 30000)  # noqa: DTZ001
    assert ts.dostimestamp(0) == datetime(1980, 1, 1, 0, 0)  # noqa: DTZ001


def test_negative_timestamps() -> None:
    # -5000.0 converted to a int representation
    assert ts.oatimestamp(13885591609694748672) == datetime(1886, 4, 22, 0, 0, tzinfo=timezone.utc)
    assert ts.oatimestamp(-5000.0) == datetime(1886, 4, 22, 0, 0, tzinfo=timezone.utc)
    # The time of day counts forward before 1899-12-30 as well, like DateTime.FromOADate in .NET
    assert ts.oatimestamp(-0.25) == datetime(1899, 12, 30, 6, 0, tzinfo=timezone.utc)
    assert ts.oatimestamp(-1.25) == datetime(1899, 12, 29, 6, 0, tzinfo=timezone.utc)
    assert ts.oatimestamp(-12.25) == datetime(1899, 12, 18, 6, 0, tzinfo=timezone.utc)
    assert ts.oatimestamp(-0.999) == datetime(1899, 12, 30, 23, 58, 33, 599999, tzinfo=timezone.utc)
    assert ts.webkittimestamp(-5000) == datetime(1600, 12, 31, 23, 59, 59, 995000, tzinfo=timezone.utc)
    assert ts.wintimestamp(-5000) == datetime(1600, 12, 31, 23, 59, 59, 999500, tzinfo=timezone.utc)
    # Rounded down, so 500 nanoseconds before the epoch is 1 microsecond before it
    assert ts.wintimestamp(-5) == datetime(1600, 12, 31, 23, 59, 59, 999999, tzinfo=timezone.utc)
    assert ts.xfstimestamp(-100000, 0) == datetime(1969, 12, 30, 20, 13, 20, tzinfo=timezone.utc)
    assert ts.ufstimestamp(-999999, -213213213213219) == datetime(1969, 12, 17, 22, 59, 47, 786786, tzinfo=timezone.utc)
    assert ts.from_unix(-0xDEADBEEF) == datetime(1851, 8, 13, 2, 4, 1, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    ("func", "args"),
    [
        pytest.param("from_unix", (253402300800,), id="from_unix-int"),
        pytest.param("from_unix", (-62135596801.0,), id="from_unix-float"),
        pytest.param("from_unix_ms", (253402300800000,), id="from_unix_ms"),
        pytest.param("from_unix_us", (253402300800000000,), id="from_unix_us"),
        pytest.param("from_unix_ns", (-62135596800000000001,), id="from_unix_ns"),
        pytest.param("xfstimestamp", (253402300800, 0), id="xfstimestamp"),
        pytest.param("wintimestamp", (2**64 - 1,), id="wintimestamp"),
        pytest.param("oatimestamp", (2958466.0,), id="oatimestamp"),
        pytest.param("webkittimestamp", (-50491123200000001,), id="webkittimestamp"),
        pytest.param("cocoatimestamp", (252423993600,), id="cocoatimestamp"),
        pytest.param("uuid1timestamp", (2**64 - 1,), id="uuid1timestamp"),
        pytest.param("golangtimestamp", (bytes.fromhex("01ffffffffffffffff00000000ffff"),), id="golangtimestamp"),
    ],
)
def test_out_of_range(func: str, args: tuple) -> None:
    """Test that timestamps outside the range of datetime raise OverflowError on every platform."""
    # The message comes from datetime and differs between CPython and PyPy
    with pytest.raises(OverflowError):
        getattr(ts, func)(*args)


def test_golang_timestamp() -> None:
    """Test if we can convert golang ``Time.time`` marshalled bytes to a datetime object."""
    timestamp = bytes.fromhex("010000000ee2221c201f08a2f6ffff")
    assert ts.golangtimestamp(timestamp) == datetime(2026, 8, 27, 11, 53, 4, 520659, tzinfo=timezone.utc)

    timestamp = bytes.fromhex("010000000ee2221c201f08a2f6003c")
    assert ts.golangtimestamp(timestamp).isoformat() == "2026-08-27T12:53:04.520659+01:00"

    # Version 2 adds the seconds of the offset, here the local mean time of Amsterdam and New York
    timestamp = bytes.fromhex("020000000df3e82140075bcd15001320")
    assert ts.golangtimestamp(timestamp).isoformat() == "1900-01-01T12:19:32.123456+00:19:32"
    timestamp = bytes.fromhex("020000000d96a2aa003b9ac9fffed8fe")
    assert ts.golangtimestamp(timestamp).isoformat() == "1850-05-31T19:03:58.999999-04:56:02"

    timestamp = bytes.fromhex("010000000ee2221c2059682f00ffff")
    with pytest.raises(ValueError, match=r"^Expected nanoseconds below 1000000000 but got 1500000000$"):
        ts.golangtimestamp(timestamp)


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        pytest.param(b"", "Expected version 1 or 2 but got b''", id="empty"),
        pytest.param(
            bytes.fromhex("030000000ee2221c201f08a2f6ffff"), "Expected version 1 or 2 but got b'\\x03'", id="version-3"
        ),
        pytest.param(
            bytes.fromhex("010000000df3e82140075bcd15001320"), "Expected 15 bytes but got 16", id="version-1-length"
        ),
        pytest.param(
            bytes.fromhex("020000000ee2221c201f08a2f6ffff"), "Expected 16 bytes but got 15", id="version-2-length"
        ),
    ],
)
def test_golang_timestamp_invalid(raw: bytes, message: str) -> None:
    """Test that golang ``Time.time`` bytes with an unsupported version or the wrong length raise a ValueError."""
    with pytest.raises(ValueError, match=f"^{re.escape(message)}$"):
        ts.golangtimestamp(raw)


@pytest.mark.benchmark
@pytest.mark.parametrize(
    ("func", "args", "expected"),
    [
        pytest.param(
            "from_unix", (1523489672,), datetime(2018, 4, 11, 23, 34, 32, tzinfo=timezone.utc), id="from_unix-int"
        ),
        pytest.param(
            "from_unix",
            (1523489672.915138,),
            datetime(2018, 4, 11, 23, 34, 32, 915138, tzinfo=timezone.utc),
            id="from_unix-float",
        ),
        pytest.param(
            "from_unix_ms",
            (1511260448882,),
            datetime(2017, 11, 21, 10, 34, 8, 882000, tzinfo=timezone.utc),
            id="from_unix_ms-int",
        ),
        pytest.param(
            "from_unix_ms",
            (1511260448882.0,),
            datetime(2017, 11, 21, 10, 34, 8, 882000, tzinfo=timezone.utc),
            id="from_unix_ms-float",
        ),
        pytest.param(
            "from_unix_us",
            (1511260448882000,),
            datetime(2017, 11, 21, 10, 34, 8, 882000, tzinfo=timezone.utc),
            id="from_unix_us",
        ),
        pytest.param(
            "from_unix_ns",
            (1523489672915138000,),
            datetime(2018, 4, 11, 23, 34, 32, 915138, tzinfo=timezone.utc),
            id="from_unix_ns",
        ),
        pytest.param(
            "xfstimestamp",
            (1582541380, 451742000),
            datetime(2020, 2, 24, 10, 49, 40, 451742, tzinfo=timezone.utc),
            id="xfstimestamp",
        ),
        pytest.param(
            "wintimestamp",
            (131679632729151380,),
            datetime(2018, 4, 11, 23, 34, 32, 915138, tzinfo=timezone.utc),
            id="wintimestamp-int",
        ),
        pytest.param(
            "wintimestamp",
            ((0xBACA7E00, 0x01DBD5F8),),
            datetime(2025, 6, 5, 9, 3, 40, tzinfo=timezone.utc),
            id="wintimestamp-tuple",
        ),
        pytest.param(
            "oatimestamp",
            (42660.171277338,),
            datetime(2016, 10, 17, 4, 6, 38, 362003, tzinfo=timezone.utc),
            id="oatimestamp-float",
        ),
        pytest.param(
            "oatimestamp",
            (4676095982878497960,),
            datetime(2016, 10, 17, 4, 6, 38, 362003, tzinfo=timezone.utc),
            id="oatimestamp-int",
        ),
        pytest.param(
            "webkittimestamp",
            (13261574439236538,),
            datetime(2021, 3, 30, 10, 40, 39, 236538, tzinfo=timezone.utc),
            id="webkittimestamp",
        ),
        pytest.param(
            "cocoatimestamp",
            (622894123,),
            datetime(2020, 9, 27, 10, 8, 43, tzinfo=timezone.utc),
            id="cocoatimestamp-int",
        ),
        pytest.param(
            "cocoatimestamp",
            (622894123.221783,),
            datetime(2020, 9, 27, 10, 8, 43, 221783, tzinfo=timezone.utc),
            id="cocoatimestamp-float",
        ),
        pytest.param(
            "uuid1timestamp",
            (137427824729151380,),
            datetime(2018, 4, 11, 23, 34, 32, 915138, tzinfo=timezone.utc),
            id="uuid1timestamp",
        ),
        pytest.param(
            "dostimestamp",
            (1391424892, 3),
            datetime(2021, 7, 15, 14, 43, 56, 30000),  # noqa: DTZ001
            id="dostimestamp",
        ),
        pytest.param(
            "golangtimestamp",
            (bytes.fromhex("010000000ee2221c201f08a2f6ffff"),),
            datetime(2026, 8, 27, 11, 53, 4, 520659, tzinfo=timezone.utc),
            id="golangtimestamp",
        ),
    ],
)
def test_benchmark_timestamp(func: str, args: tuple, expected: datetime, benchmark: BenchmarkFixture) -> None:
    """Benchmark the conversion of each timestamp format to a datetime object."""
    assert benchmark(getattr(ts, func), *args) == expected
