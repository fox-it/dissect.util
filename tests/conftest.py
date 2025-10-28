import importlib.util
from types import ModuleType

import pytest

HAS_BENCHMARK = importlib.util.find_spec("pytest_benchmark") is not None


def pytest_configure(config: pytest.Config) -> None:
    if not HAS_BENCHMARK:
        # If we don't have pytest-benchmark (or pytest-codspeed) installed, register the benchmark marker ourselves
        # to avoid pytest warnings
        config.addinivalue_line("markers", "benchmark: mark test for benchmarking (requires pytest-benchmark)")


def pytest_runtest_setup(item: pytest.Item) -> None:
    if not HAS_BENCHMARK and item.get_closest_marker("benchmark") is not None:
        pytest.skip("pytest-benchmark is not installed")


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--force-native", action="store_true", default=False, help="run native tests, not allowing fallbacks"
    )


def _native_or_python(module: ModuleType, name: str, request: pytest.FixtureRequest) -> ModuleType:
    if request.param:
        if not (module := getattr(module, f"{name}_native", None)):
            (pytest.fail if request.config.getoption("--force-native") else pytest.skip)(
                "_native module is unavailable"
            )

        return module
    return getattr(module, f"{name}_python", None)


@pytest.fixture(scope="session", params=[True, False], ids=["native", "python"])
def lz4(request: pytest.FixtureRequest) -> ModuleType:
    from dissect.util import compression

    return _native_or_python(compression, "lz4", request)


@pytest.fixture(scope="session", params=[True, False], ids=["native", "python"])
def lzo(request: pytest.FixtureRequest) -> ModuleType:
    from dissect.util import compression

    return _native_or_python(compression, "lzo", request)


@pytest.fixture(scope="session", params=[True, False], ids=["native", "python"])
def crc32c(request: pytest.FixtureRequest) -> ModuleType:
    from dissect.util import hash

    return _native_or_python(hash, "crc32c", request)
