from __future__ import annotations

import pytest

from dissect.util.feature import Feature, FeatureError, feature, feature_enabled


def test_feature_flags() -> None:
    def fallback() -> bool:
        return False

    @feature(Feature.BETA, fallback)
    def experimental() -> bool:
        return True

    @feature(Feature.ADVANCED, fallback)
    def advanced() -> bool:
        return True

    @feature(Feature.LATEST)
    def latest() -> bool:
        return True

    @feature("expert")
    def expert() -> bool:
        return True

    assert experimental() is False
    assert advanced() is False
    assert latest() is True
    with pytest.raises(FeatureError):
        assert expert() is True


def test_feature_flag_inline() -> None:
    assert feature_enabled(Feature.BETA) is False
    assert feature_enabled(Feature.LATEST) is True
