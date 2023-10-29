import pytest

from dissect.util.feature import (
    Feature,
    FeatureException,
    check_flags,
    feature,
    feature_enabled,
)


def test_feature_flags() -> None:
    def fallback():
        return False

    @feature(Feature.BETA, fallback)
    def experimental():
        return True

    @feature(Feature.NOVICE, fallback)
    def novice():
        return True

    @feature(Feature.LATEST)
    def latest():
        return True

    @feature("expert")
    def expert():
        return True

    assert experimental() is False
    assert novice() is True
    assert latest() is True
    with pytest.raises(FeatureException):
        assert expert() is True


def test_feature_flag_verification() -> None:
    with pytest.raises(FeatureException):
        check_flags(["chaotic"])


def test_feature_flag_inline() -> None:
    assert feature_enabled(Feature.BETA) is False
    assert feature_enabled(Feature.LATEST) is True
