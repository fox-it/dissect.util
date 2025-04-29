from types import ModuleType

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--force-native", action="store_true", default=False, help="run native tests, not allowing fallbacks"
    )


def _native_or_python(name: str, request: pytest.FixtureRequest) -> ModuleType:
    from dissect.util import compression

    if request.param:
        if not (module := getattr(compression, f"{name}_native", None)):
            (pytest.fail if request.config.getoption("--force-native") else pytest.skip)(
                "_native module is unavailable"
            )

        return module
    return getattr(compression, f"{name}_python", None)


@pytest.fixture(scope="session", params=[True, False], ids=["native", "python"])
def lz4(request: pytest.FixtureRequest) -> ModuleType:
    return _native_or_python("lz4", request)


@pytest.fixture(scope="session", params=[True, False], ids=["native", "python"])
def lzo(request: pytest.FixtureRequest) -> ModuleType:
    return _native_or_python("lzo", request)
