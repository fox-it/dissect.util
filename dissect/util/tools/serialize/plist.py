from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from dissect.util.serialize.plist import NSKeyedArchiver, NSObject


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=Path, help="NSKeyedArchiver plist file to dump")
    args = parser.parse_args()

    with args.file.open("rb") as fh:
        try:
            obj = NSKeyedArchiver(fh)
        except ValueError as e:
            print(e)
            return 1

        print(obj)
        print_object(obj.top)
    return 0


def print_object(obj: Any, indent: int = 0, seen: set | None = None) -> None:
    if seen is None:
        seen = set()

    try:
        if obj in seen:
            print(fmt(f"Recursive -> {obj}", indent))
            return
    except Exception:  # noqa: S110
        pass

    if isinstance(obj, list):
        for i, v in enumerate(obj):
            print(fmt(f"[{i}]:", indent))
            print_object(v, indent + 1, seen)

    elif isinstance(obj, dict | NSObject):
        if isinstance(obj, NSObject):
            print(fmt(obj, indent))
            try:
                seen.add(obj)
            except TypeError:
                pass

        for k in sorted(obj.keys()):
            print(fmt(f"{k}:", indent + 1))
            print_object(obj[k], indent + 2, seen)

    else:
        print(fmt(obj, indent))


def fmt(obj: Any, indent: int) -> str:
    return f"{' ' * (indent * 4)}{obj}"


if __name__ == "__main__":
    sys.exit(main())
