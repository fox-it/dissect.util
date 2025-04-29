import platform
from datetime import datetime, timedelta, timezone
from importlib import reload
from types import ModuleType
from unittest.mock import patch

import pytest


@pytest.fixture(params=["windows", "emscripten", "linux"])
def imported_ts(request: pytest.FixtureRequest) -> ModuleType:
    with patch.object(platform, "system", return_value=request.param):
        from dissect.util import ts

        return reload(ts)


@pytest.fixture
def ts() -> ModuleType:
    from dissect.util import ts

    return reload(ts)


def test_now(ts: ModuleType) -> None:
    ts_now = ts.now()
    datetime_now = datetime.now(timezone.utc)
    time_diff = datetime_now - ts_now

    # Should be no difference, so only set microseconds equal to remove processing time difference
    assert timedelta(microseconds=time_diff.microseconds) == time_diff
    assert ts_now.tzinfo == timezone.utc


def test_unix_now(imported_ts: ModuleType) -> None:
    timestamp = imported_ts.unix_now()

    assert isinstance(timestamp, int)
    assert datetime.fromtimestamp(timestamp, tz=timezone.utc).microsecond == 0


def test_unix_now_ms(imported_ts: ModuleType) -> None:
    timestamp = imported_ts.unix_now_ms()

    assert isinstance(timestamp, int)
    assert imported_ts.from_unix_ms(timestamp).microsecond == (timestamp % 1e3) * 1000


def test_unix_now_us(imported_ts: ModuleType) -> None:
    timestamp = imported_ts.unix_now_us()

    assert isinstance(timestamp, int)
    assert imported_ts.from_unix_us(timestamp).microsecond == timestamp % 1e6


def test_unix_now_ns(imported_ts: ModuleType) -> None:
    timestamp = imported_ts.unix_now_ns()

    assert isinstance(timestamp, int)
    assert imported_ts.from_unix_ns(timestamp).microsecond == int((timestamp // 1000) % 1e6)


def test_to_unix(ts: ModuleType) -> None:
    dt = datetime(2018, 4, 11, 23, 34, 32, 915138, tzinfo=timezone.utc)
    assert ts.to_unix(dt) == 1523489672


def test_to_unix_ms(ts: ModuleType) -> None:
    dt = datetime(2018, 4, 11, 23, 34, 32, 915000, tzinfo=timezone.utc)
    assert ts.to_unix_ms(dt) == 1523489672915


def test_to_unix_us(ts: ModuleType) -> None:
    dt = datetime(2018, 4, 11, 23, 34, 32, 915138, tzinfo=timezone.utc)
    assert ts.to_unix_us(dt) == 1523489672915138


def test_to_unix_ns(ts: ModuleType) -> None:
    dt = datetime(2018, 4, 11, 23, 34, 32, 915138, tzinfo=timezone.utc)
    assert ts.to_unix_ns(dt) == 1523489672915138000


def test_from_unix(imported_ts: ModuleType) -> None:
    assert imported_ts.from_unix(1523489672) == datetime(2018, 4, 11, 23, 34, 32, tzinfo=timezone.utc)


def test_from_unix_ms(imported_ts: ModuleType) -> None:
    assert imported_ts.from_unix_ms(1511260448882) == datetime(2017, 11, 21, 10, 34, 8, 882000, tzinfo=timezone.utc)


def test_from_unix_us(imported_ts: ModuleType) -> None:
    assert imported_ts.from_unix_us(1511260448882000) == datetime(2017, 11, 21, 10, 34, 8, 882000, tzinfo=timezone.utc)


def test_from_unix_ns(imported_ts: ModuleType) -> None:
    assert imported_ts.from_unix_ns(1523489672915138048) == datetime(
        2018, 4, 11, 23, 34, 32, 915138, tzinfo=timezone.utc
    )


def test_xfstimestamp(imported_ts: ModuleType) -> None:
    assert imported_ts.xfstimestamp(1582541380, 451742903) == datetime(
        2020, 2, 24, 10, 49, 40, 451743, tzinfo=timezone.utc
    )


def test_ufstimestamp(imported_ts: ModuleType) -> None:
    assert imported_ts.ufstimestamp(1582541380, 451742903) == datetime(
        2020, 2, 24, 10, 49, 40, 451743, tzinfo=timezone.utc
    )


def test_wintimestamp(imported_ts: ModuleType) -> None:
    assert imported_ts.wintimestamp(131679632729151386) == datetime(
        2018, 4, 11, 23, 34, 32, 915138, tzinfo=timezone.utc
    )


def test_oatimestamp(imported_ts: ModuleType) -> None:
    dt = datetime(2016, 10, 17, 4, 6, 38, 362003, tzinfo=timezone.utc)
    assert imported_ts.oatimestamp(42660.171277338) == dt
    assert imported_ts.oatimestamp(4676095982878497960) == dt
    assert imported_ts.oatimestamp(-4542644417712532139) == datetime(1661, 4, 17, 11, 30, tzinfo=timezone.utc)


def test_webkittimestamp(imported_ts: ModuleType) -> None:
    assert imported_ts.webkittimestamp(13261574439236538) == datetime(
        2021, 3, 30, 10, 40, 39, 236538, tzinfo=timezone.utc
    )


def test_cocoatimestamp(imported_ts: ModuleType) -> None:
    assert imported_ts.cocoatimestamp(622894123) == datetime(2020, 9, 27, 10, 8, 43, tzinfo=timezone.utc)
    assert imported_ts.cocoatimestamp(622894123.221783) == datetime(2020, 9, 27, 10, 8, 43, 221783, tzinfo=timezone.utc)


def test_dostimestamp(imported_ts: ModuleType) -> None:
    assert imported_ts.dostimestamp(1391424892, 3) == datetime(2021, 7, 15, 14, 43, 56, 30000)  # noqa: DTZ001
    assert imported_ts.dostimestamp(0) == datetime(1980, 1, 1, 0, 0)  # noqa: DTZ001


def test_negative_timestamps(imported_ts: ModuleType) -> None:
    # -5000.0 converted to a int representation
    assert imported_ts.oatimestamp(13885591609694748672) == datetime(1886, 4, 22, 0, 0, tzinfo=timezone.utc)
    assert imported_ts.oatimestamp(-5000.0) == datetime(1886, 4, 22, 0, 0, tzinfo=timezone.utc)
    assert imported_ts.webkittimestamp(-5000) == datetime(1600, 12, 31, 23, 59, 59, 995001, tzinfo=timezone.utc)
    assert imported_ts.wintimestamp(-5000) == datetime(1600, 12, 31, 23, 59, 59, 999500, tzinfo=timezone.utc)
    assert imported_ts.xfstimestamp(-100000, 0) == datetime(1969, 12, 30, 20, 13, 20, tzinfo=timezone.utc)
    assert imported_ts.ufstimestamp(-999999, -213213213213219) == datetime(
        1969, 12, 17, 22, 59, 47, 786787, tzinfo=timezone.utc
    )
    assert imported_ts.from_unix(-0xDEADBEEF) == datetime(1851, 8, 13, 2, 4, 1, tzinfo=timezone.utc)
