import functools
import os
from enum import Enum
from typing import Callable, Optional


# Register feature flags in a central place to avoid chaos
class Feature(Enum):
    NOVICE = "novice"
    LATEST = "latest"
    BETA = "beta"


# This set defines the valid flags
DISSECT_FEATURE_SET = set(item for item in Feature)

# Defines the default flags (as strings)
DISSECT_FEATURES_DEFAULT = "novice/latest"

# Defines the environment variable to read the flags from
DISSECT_FEATURES_ENV = "DISSECT_FEATURES"


class FeatureException(RuntimeError):
    pass


def check_flags(flags: list[Feature]) -> list[Feature]:
    for flag in flags:
        if flag not in DISSECT_FEATURE_SET:
            raise FeatureException(f"Invalid feature flag: {flag} choose from: {DISSECT_FEATURE_SET}")
    return flags


@functools.cache
def feature_flags() -> list[Feature]:
    return check_flags([Feature(name) for name in os.getenv(DISSECT_FEATURES_ENV, DISSECT_FEATURES_DEFAULT).split("/")])


@functools.cache
def feature_enabled(feature: Feature) -> bool:
    return feature in feature_flags()


def feature_disabled_stub() -> None:
    raise FeatureException("This feature has been disabled.")


def feature(flag: Feature, alternative: Optional[Callable] = feature_disabled_stub) -> Callable:
    """Usage:

    @feature(F_SOME_FLAG, altfunc)
    def my_func( ... ) -> ...

    Where F_SOME_FLAG is the feature you want to check for and
    altfunc is the alternative function to serve
    if the feature flag is NOT set.
    """

    def decorator(func):
        if feature_enabled(flag):
            return func
        else:
            return alternative

    return decorator
