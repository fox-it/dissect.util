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


@pytest.fixture(scope="session", params=[True, False], ids=["native", "python"])
def _native(request: pytest.FixtureRequest, pytestconfig: pytest.Config) -> ModuleType:
    if request.param:
        try:
            import dissect.util._native
        except ImportError:
            (pytest.fail if pytestconfig.getoption("--force-native") else pytest.skip)("_native module is unavailable")
        else:
            return dissect.util._native

    return None


@pytest.fixture(scope="session")
def lz4(_native: ModuleType) -> ModuleType:
    if _native:
        return _native.compression.lz4

    import dissect.util.compression.lz4

    return dissect.util.compression.lz4


@pytest.fixture(scope="session")
def lzo(_native: ModuleType) -> ModuleType:
    if _native:
        return _native.compression.lzo

    import dissect.util.compression.lzo

    return dissect.util.compression.lzo
