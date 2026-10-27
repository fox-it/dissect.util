# Reference: https://setuptools.pypa.io/en/latest/build_meta.html#dynamic-build-dependencies-and-other-build-meta-tweaks
from __future__ import annotations

import os
import shlex
import sys
from typing import Any

import setuptools.build_meta
from setuptools.build_meta import *  # noqa: F403


def get_requires_for_build_wheel(config_settings: dict[str, Any] | None = None) -> list[str]:
    base = setuptools.build_meta.get_requires_for_build_wheel(config_settings)

    if os.getenv("BUILD_RUST", "").lower() in {"1", "true"} or (config_settings and "--build-rust" in config_settings):
        return [*base, "setuptools-rust"]

    return base


def build_wheel(
    wheel_directory: str, config_settings: dict[str, Any] | None = None, metadata_directory: str | None = None
) -> str:
    if sys.implementation.name != "cpython" and config_settings and "--build-option" in config_settings:
        # Only CPython has a stable ABI, and since setuptools 84.2 asking for it elsewhere names the extension
        # like a CPython abi3 one, which PyPy on Windows cannot import
        # Reference: https://github.com/pypa/setuptools/issues/5367
        option = config_settings["--build-option"]
        args = shlex.split(option) if isinstance(option, str) else list(option)
        config_settings = {
            **config_settings,
            "--build-option": [arg for arg in args if not arg.startswith("--py-limited-api")],
        }

    return setuptools.build_meta.build_wheel(wheel_directory, config_settings, metadata_directory)
