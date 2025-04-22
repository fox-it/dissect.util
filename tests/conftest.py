from types import ModuleType

import pytest


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
