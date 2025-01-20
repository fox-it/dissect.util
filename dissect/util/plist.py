from __future__ import annotations

import plistlib
import uuid
from collections import UserDict
from datetime import datetime
from typing import TYPE_CHECKING, Any, BinaryIO, Callable, TypedDict, Union, cast

from dissect.util.ts import cocoatimestamp

if TYPE_CHECKING:
    from collections.abc import Iterable


_Value = Union[
    bool,
    bytes,
    int,
    float,
    str,
    datetime,
    uuid.UUID,
    "NSDictionary",
    "NSObject",
    "_NSClass",
    list["_Value"],
    dict[str, "_Value"],
    None,
]


_NSKeyedArchiver = TypedDict(
    "_NSKeyedArchiver",
    {
        "$version": int,
        "$archiver": str,
        "$top": dict[str, plistlib.UID],
        "$objects": list["_Value | _NSObject"],
    },
)
_NSClass = TypedDict(
    "_NSClass",
    {
        "$classname": str,
        "$classes": list[str],
    },
)
_NSObject = TypedDict(
    "_NSObject",
    {
        "$class": plistlib.UID,
    },
)
_NSArray = TypedDict(
    "_NSArray",
    {
        "$class": plistlib.UID,
        "NS.objects": list[_Value | plistlib.UID],
    },
)
_NSMutableArray = _NSMutableSet = _NSSet = _NSArray
_NSDictionary = TypedDict(
    "_NSDictionary",
    {
        "$class": plistlib.UID,
        "NS.keys": list[plistlib.UID],
        "NS.objects": list[plistlib.UID],
    },
)
_NSMutableDictionary = _NSDictionary
_NSData = TypedDict(
    "_NSData",
    {
        "$class": plistlib.UID,
        "NS.data": bytes,
    },
)
_NSMutableData = _NSData
_NSDate = TypedDict(
    "_NSDate",
    {
        "$class": plistlib.UID,
        "NS.time": int,
    },
)
_NSUUID = TypedDict(
    "_NSUUID",
    {
        "$class": plistlib.UID,
        "NS.uuidbytes": bytes,
    },
)
_NSURL = TypedDict(
    "_NSURL",
    {
        "$class": plistlib.UID,
        "NS.base": plistlib.UID,
        "NS.relative": plistlib.UID,
    },
)


class NSKeyedArchiver:
    def __init__(self, fh: BinaryIO):
        plist: Any = plistlib.load(fh)

        if not isinstance(plist, dict) or not all(
            key in plist for key in ["$version", "$archiver", "$top", "$objects"]
        ):
            raise ValueError("File is not an NSKeyedArchiver plist")

        self.plist: _NSKeyedArchiver = cast(_NSKeyedArchiver, plist)
        self._objects = self.plist.get("$objects", [])
        self._cache: dict[int, _Value] = {}

        self.top: dict[str, _Value] = {}
        for name, value in self.plist.get("$top", {}).items():
            self.top[name] = self._parse(value)

    def __getitem__(self, key: str) -> _Value:
        return self.top[key]

    def __repr__(self) -> str:
        return f"<NSKeyedArchiver top={self.top}>"

    def get(self, key: str, default: _Value | None = None) -> _Value:
        return self.top.get(key, default)

    def _parse(self, uid: _Value | plistlib.UID) -> _Value:
        if not isinstance(uid, plistlib.UID):
            return uid

        num = uid.data
        if num in self._cache:
            return self._cache[num]
        result = self._parse_obj(self._objects[num])
        self._cache[num] = result
        return result

    def _parse_obj(self, obj: _Value | _NSObject) -> _Value:
        if isinstance(obj, dict):
            if klass := obj.get("$class"):
                klass_name = cast(_NSClass, self._parse(klass)).get("$classname")
                return CLASSES.get(klass_name, NSObject)(self, obj)
            return cast(dict[Any, Any], obj)

        if isinstance(obj, list):
            return list(map(self._parse, obj))

        if isinstance(obj, (bool, bytes, int, float)) or obj is None:
            return obj

        if isinstance(obj, str):
            return None if obj == "$null" else obj

        return None


class NSObject:
    def __init__(self, nskeyed: NSKeyedArchiver, obj: _NSObject):
        self.nskeyed = nskeyed
        self.obj = obj

        self._class: _NSClass = cast(_NSClass, nskeyed._parse(obj.get("$class", {})))
        self._classname = self._class.get("$classname", "Unknown")
        self._classes = self._class.get("$classes", [])

    def __getitem__(self, attr: str) -> _Value:
        return self.nskeyed._parse(cast(_Value, self.obj[attr]))

    def __getattr__(self, attr: str) -> _Value:
        try:
            return self[attr]
        except KeyError:
            raise AttributeError(attr)

    def __repr__(self) -> str:
        return f"<{self._classname}>"

    def keys(self) -> Iterable[str]:
        return self.obj.keys()

    def get(self, attr: str, default: object | None = None) -> object | None:
        try:
            return self[attr]
        except KeyError:
            return default


class NSDictionary(UserDict, NSObject):  # type: ignore
    def __init__(self, nskeyed: NSKeyedArchiver, obj: _NSDictionary):
        NSObject.__init__(self, nskeyed, obj)
        self.data: dict[_Value, Any] = {nskeyed._parse(key): obj for key, obj in zip(obj["NS.keys"], obj["NS.objects"])}

    def __repr__(self) -> str:
        return NSObject.__repr__(self)

    def __getitem__(self, key: str) -> _Value:
        return self.nskeyed._parse(self.data[key])


def parse_nsarray(nskeyed: NSKeyedArchiver, obj: _NSArray | _NSMutableArray) -> list[_Value]:
    return list(map(nskeyed._parse, obj["NS.objects"]))


def parse_nsset(nskeyed: NSKeyedArchiver, obj: _NSSet | _NSMutableSet) -> list[_Value]:
    # Some values are not hashable, so return as list
    return parse_nsarray(nskeyed, obj)


def parse_nsdata(nskeyed: NSKeyedArchiver, obj: _NSData) -> bytes:
    return obj["NS.data"]


def parse_nsdate(nskeyed: NSKeyedArchiver, obj: _NSDate) -> datetime:
    return cocoatimestamp(obj["NS.time"])


def parse_nsuuid(nskeyed: NSKeyedArchiver, obj: _NSUUID) -> uuid.UUID:
    return uuid.UUID(bytes=obj["NS.uuidbytes"])


def parse_nsurl(nskeyed: NSKeyedArchiver, obj: _NSURL) -> str:
    base = cast(str, nskeyed._parse(obj["NS.base"]))
    relative = cast(str, nskeyed._parse(obj["NS.relative"]))
    if base:
        return f"{base}/{relative}"
    return relative


CLASSES: dict[str, Callable[[NSKeyedArchiver, Any], _Value]] = {
    "NSArray": parse_nsarray,
    "NSMutableArray": parse_nsarray,
    "NSDictionary": NSDictionary,
    "NSMutableDictionary": NSDictionary,
    "NSSet": parse_nsset,
    "NSMutableSet": parse_nsset,
    "NSData": parse_nsdata,
    "NSMutableData": parse_nsdata,
    "NSDate": parse_nsdate,
    "NSUUID": parse_nsuuid,
    "NSURL": parse_nsurl,
    "NSNull": lambda nskeyed, obj: None,
}
