import functools
import os
from enum import Enum
from typing import Callable, Optional


# Register feature flags in a central place to avoid chaos
class Feature(Enum):
    LATEST = "latest"
    ADVANCED = "advanced"
    BETA = "beta"


# Defines the default flags (as strings)
DISSECT_FEATURES_DEFAULT = "latest"

# Defines the environment variable to read the flags from
DISSECT_FEATURES_ENV = "DISSECT_FEATURES"


class FeatureException(RuntimeError):
    pass


@functools.cache
def feature_flags() -> list[Feature]:
    return [Feature(name) for name in os.getenv(DISSECT_FEATURES_ENV, DISSECT_FEATURES_DEFAULT).split("/")]


@functools.cache
def feature_enabled(feature: Feature) -> bool:
    return feature in feature_flags()


def feature_disabled_stub() -> None:
    raise FeatureException("This feature has been disabled.")


def feature(flag: Feature, alternative: Optional[Callable] = feature_disabled_stub) -> Callable:
    """
    Usage::

        @feature(Feature.SOME_FLAG, fallback)
        def my_func( ... ) -> ...

    Where ``SOME_FLAG`` is the feature you want to check for and ``fallback`` is the alternative function to serve
    if the feature flag is NOT set.
    """

    def decorator(func):
        return func if feature_enabled(flag) else alternative

    return decorator
