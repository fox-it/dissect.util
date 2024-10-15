from __future__ import annotations

import functools
import os
from enum import Enum
from typing import Callable, NoReturn


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
    """Use this function for block-level feature flag control.

    Usage::

        def parse_blob():
            if feature_enabled(Feature.BETA):
                self._parse_fast_experimental()
            else:
                self._parse_normal()

    """
    return feature in feature_flags()


def feature(flag: Feature, alternative: Callable | None = None) -> Callable:
    """Feature flag decorator allowing you to guard a function behind a feature flag.

    Usage::

        @feature(Feature.SOME_FLAG, fallback)
        def my_func( ... ) -> ...

    Where ``SOME_FLAG`` is the feature you want to check for and ``fallback`` is the alternative function to serve
    if the feature flag is NOT set.
    """

    if alternative is None:

        def alternative() -> NoReturn:
            raise FeatureException(
                "\n".join(
                    [
                        "Feature disabled.",
                        f"Set FLAG '{flag}' in {DISSECT_FEATURES_ENV} to enable.",
                        "See https://docs.dissect.tools/en/latest/advanced/flags.html",
                    ]
                )
            )

    def decorator(func: Callable) -> Callable:
        return func if feature_enabled(flag) else alternative

    return decorator
