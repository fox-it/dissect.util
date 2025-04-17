import datetime
import sys
import uuid
from plistlib import UID
from unittest.mock import patch

import pytest

from dissect.util.plist import NSKeyedArchiver


@pytest.mark.skipif(sys.version_info < (3, 8), reason="requires python3.8 or higher")
def test_plist_nskeyedarchiver() -> None:
    data = {
        "$version": 100000,
        "$archiver": "NSKeyedArchiver",
        "$top": {
            "root": UID(1),
        },
        "$objects": [
            # 0
            "$null",
            # 1
            {
                "$class": UID(2),
                "Null": UID(0),
                "Integer": 1337,
                "String": UID(3),
                "Bytes": b"bytes",
                "Data": UID(4),
                "UUID": UID(6),
                "Date": UID(8),
                "URL": UID(10),
                "URLBaseless": UID(13),
                "Array": UID(15),
                "Set": UID(17),
                "Dict": UID(19),
            },
            # 2
            {
                "$classname": "TestObject",
                "$classes": ["TestObject", "NSObject"],
            },
            # 3
            "TestString",
            # 4
            {
                "$class": UID(5),
                "NS.data": b"\x00" * 4,
            },
            # 5
            {
                "$classname": "NSMutableData",
                "$classes": ["NSMutableData", "NSData", "NSObject"],
            },
            # 6
            {
                "$class": UID(7),
                "NS.uuidbytes": b"\x00" * 16,
            },
            # 7
            {
                "$classname": "NSUUID",
                "$classes": ["NSUUID", "NSObject"],
            },
            # 8
            {
                "$class": UID(9),
                "NS.time": 660837352.084823,
            },
            # 9
            {
                "$classname": "NSDate",
                "$classes": ["NSDate", "NSObject"],
            },
            # 10
            {
                "$class": UID(14),
                "NS.base": UID(11),
                "NS.relative": UID(12),
            },
            # 11
            "http://base",
            # 12
            "relative",
            # 13
            {
                "$class": UID(14),
                "NS.base": UID(0),
                "NS.relative": UID(12),
            },
            # 14
            {
                "$classname": "NSURL",
                "$classes": ["NSURL", "NSObject"],
            },
            # 15
            {
                "$class": UID(16),
                "NS.objects": [1, UID(3)],
            },
            # 16
            {
                "$classname": "NSMutableArray",
                "$classes": ["NSMutableArray", "NSArray", "NSObject"],
            },
            # 17
            {
                "$class": UID(18),
                "NS.objects": [1, UID(3)],
            },
            # 18
            {
                "$classname": "NSMutableSet",
                "$classes": ["NSMutableSet", "NSSet", "NSObject"],
            },
            # 19
            {
                "$class": UID(21),
                "NS.keys": [UID(20)],
                "NS.objects": [UID(3)],
            },
            # 20
            "DictKey",
            # 21
            {
                "$classname": "NSMutableDictionary",
                "$classes": ["NSMutableDictionary", "NSDictionary", "NSObject"],
            },
        ],
    }
    with patch("plistlib.load", return_value=data):
        obj = NSKeyedArchiver(None)
        assert "root" in obj.top

        root = obj["root"]
        assert root._classname == "TestObject"
        assert root.Null is None
        assert root.Integer == 1337
        assert root.String == "TestString"
        assert root.Bytes == b"bytes"
        assert root.Data == b"\x00" * 4
        assert root.UUID == uuid.UUID("00000000-0000-0000-0000-000000000000")  # noqa: SIM300
        assert root.Date == datetime.datetime(2021, 12, 10, 13, 55, 52, 84823, tzinfo=datetime.timezone.utc)
        assert root.URL == "http://base/relative"
        assert root.URLBaseless == "relative"
        assert root.Array == root.Set == [1, "TestString"]
        assert list(root.Dict.items()) == [("DictKey", "TestString")]
