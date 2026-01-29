from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

import pytest

from dissect.util.compression import snappy

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture


PARAMS = (
    ("data", "digest"),
    [
        pytest.param(
            "ac0208616263fe0300fe0300fe0300fe0300a20300",
            "d9f5aeb06abebb3be3f38adec9a2e3b94228d52193be923eb4e24c9b56ee0930",
            id="basic",
        ),
        pytest.param(
            "df6df4b6014c6f72656d20697073756d20646f6c6f722073697420616d65"
            "7420636f6e73656374657475722061646970697363696e6720656c69742e"
            "20517569737175652066617563696275732065782073617069656e207669"
            "7461652070656c6c656e7465737175652073656d20706c6163657261742e"
            "20496e20696420637572737573206d69207072657469756d2074656c6c75"
            "73206475697320636f6e76616c6c69732e2054656d707573206c656f2065"
            "752061656e65616e20736564206469616d2075726e612074656d706f722e"
            "2050756c76696e617220766976616d7573206672696e67696c6c61206c61"
            "637573206e6563206d6574757320626962656e64756d2065676573746173"
            "2e20496163756c6973206d61737361206e69736c206d616c657375616461"
            "206c6163696e696120696e7465676572206e756e6320706f73756572652e"
            "2055742068656e6472657269742073656d7065722076656c20636c617373"
            "20617074656e742074616369746920736f63696f7371752e204164206c69"
            "746f726120746f727175656e742070657220636f6e75626961206e6f7374"
            "726120696e636570746f732068696d656e61656f732e0a0afeb701feb701"
            "feb701feb701feb701feb701feb701feb701feb701feb701feb701feb701"
            "feb701feb701feb701feb701feb701feb701feb701feb701feb701feb701"
            "feb701feb701feb701feb701feb701feb701feb701feb701feb701feb701"
            "feb701feb701feb701feb701feb701feb701feb701feb701feb701feb701"
            "feb701feb701feb701feb701feb701feb701feb701feb701feb701feb701"
            "feb701feb701feb701feb701feb701feb701feb701feb701feb701feb701"
            "feb701feb701feb701feb701feb701feb701feb701feb701feb701feb701"
            "feb701feb701feb701feb701feb701feb701feb701feb701feb701feb701"
            "feb701feb701feb701feb701feb701feb701feb701feb701feb701feb701"
            "feb701feb701feb701feb701feb701feb701feb701feb701feb701feb701"
            "feb701feb701feb701feb701feb701feb701feb701feb701feb701feb701"
            "feb701feb701feb701feb701feb701feb701feb701feb701feb701feb701"
            "feb701feb701feb701feb701feb701feb701feb701feb701feb701feb701"
            "feb701feb701feb701feb701feb701feb701feb701feb701feb701feb701"
            "feb701feb701feb701feb701feb701feb701feb701feb701feb701feb701"
            "feb701feb701feb701feb701feb701feb701feb701feb701feb701feb701"
            "feb701feb701feb701feb701feb701feb701feb701feb701feb701feb701"
            "feb701feb701feb701feb701feb701feb701feb701feb701feb701feb701"
            "feb701feb701feb701feb701feb701feb701feb701feb701feb701feb701"
            "feb701feb701feb701feb701feb701feb701feb701feb701feb701feb701"
            "feb701feb701feb701feb701feb701feb701feb701feb701feb701feb701"
            "9eb701",
            "73d3dd96ca2e2f0144a117019256d770ee7c6febeaee09b24956c723ae22b529",
            id="large",
        ),
    ],
)


@pytest.mark.parametrize(*PARAMS)
def test_snappy_decompress(data: str, digest: str) -> None:
    assert hashlib.sha256(snappy.decompress(bytes.fromhex(data))).hexdigest() == digest


@pytest.mark.benchmark
@pytest.mark.parametrize(*PARAMS)
def test_benchmark_snappy_decompress(data: str, digest: str, benchmark: BenchmarkFixture) -> None:
    assert hashlib.sha256(benchmark(snappy.decompress, bytes.fromhex(data))).hexdigest() == digest
