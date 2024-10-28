from types import ModuleType

import pytest


@pytest.fixture(scope="session", params=[True, False], ids=["native", "python"])
def lz4(request: pytest.FixtureRequest) -> ModuleType:
    if request.param:
        return pytest.importorskip("dissect.util._native", reason="No _native module available").compression.lz4

    return pytest.importorskip("dissect.util.compression.lz4")


@pytest.fixture(scope="session", params=[True, False], ids=["native", "python"])
def lzo(request: pytest.FixtureRequest) -> ModuleType:
    if request.param:
        return pytest.importorskip("dissect.util._native", reason="No _native module available").compression.lzo

    return pytest.importorskip("dissect.util.compression.lzo")
