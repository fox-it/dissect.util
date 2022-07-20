import uuid
import plistlib

from dissect.util.ts import cocoatimestamp

from collections import UserDict


class NSKeyedArchiver:
    def __init__(self, fh):
        self.plist = plistlib.load(fh)

        if not isinstance(self.plist, dict) or not all(
            key in self.plist for key in ["$version", "$archiver", "$top", "$objects"]
        ):
            raise ValueError("File is not an NSKeyedArchiver plist")

        self._objects = self.plist.get("$objects")
        self._cache = {}

        self.top = {}
        for name, value in self.plist.get("$top", {}).items():
            self.top[name] = self._parse(value)

    def __getitem__(self, key):
        return self.top[key]

    def get(self, key, default=None):
        return self.top.get(key, default)

    def _parse(self, uid):
        if not isinstance(uid, plistlib.UID):
            return uid

        num = uid.data
        if num in self._cache:
            return self._cache[num]
        result = self._parse_obj(self._objects[num])
        self._cache[num] = result
        return result

    def _parse_obj(self, obj):
        if isinstance(obj, dict):
            klass = obj.get("$class")
            if klass:
                klass_name = self._parse(klass).get("$classname")
                return CLASSES.get(klass_name, NSObject)(self, obj)
            return obj

        if isinstance(obj, list):
            return list(map(self._parse, obj))

        if isinstance(obj, (bool, bytes, int, float)) or obj is None:
            return obj

        if isinstance(obj, str):
            return None if obj == "$null" else obj

    def __repr__(self):
        return f"<NSKeyedArchiver top={self.top}>"


class NSObject:
    def __init__(self, nskeyed, obj):
        self.nskeyed = nskeyed
        self.obj = obj

        self._class = nskeyed._parse(obj.get("$class", {}))
        self._classname = self._class.get("$classname", "Unknown")
        self._classes = self._class.get("$classes", [])

    def keys(self):
        return self.obj.keys()

    def get(self, attr, default=None):
        try:
            return self[attr]
        except KeyError:
            return default

    def __getitem__(self, attr):
        obj = self.obj[attr]
        return self.nskeyed._parse(obj)

    def __getattr__(self, attr):
        try:
            return self[attr]
        except KeyError:
            raise AttributeError(attr)

    def __repr__(self):
        return f"<{self._classname}>"


class NSDictionary(UserDict, NSObject):
    def __init__(self, nskeyed, obj):
        NSObject.__init__(self, nskeyed, obj)
        self.data = {nskeyed._parse(key): obj for key, obj in zip(obj["NS.keys"], obj["NS.objects"])}

    def __getitem__(self, key):
        return self.nskeyed._parse(self.data[key])

    def __repr__(self):
        return NSObject.__repr__(self)


def parse_nsarray(nskeyed, obj):
    return list(map(nskeyed._parse, obj["NS.objects"]))


def parse_nsset(nskeyed, obj):
    # Some values are not hashable, so return as list
    return parse_nsarray(nskeyed, obj)


def parse_nsdata(nskeyed, obj):
    return obj["NS.data"]


def parse_nsdate(nskeyed, obj):
    return cocoatimestamp(obj["NS.time"])


def parse_nsuuid(nskeyed, obj):
    return uuid.UUID(bytes=obj["NS.uuidbytes"])


def parse_nsurl(nskeyed, obj):
    base = nskeyed._parse(obj["NS.base"])
    relative = nskeyed._parse(obj["NS.relative"])
    if base:
        return "/".join([base, relative])
    return relative


CLASSES = {
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
