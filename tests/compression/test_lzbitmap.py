from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

import pytest

from dissect.util.compression import lzbitmap

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture


@pytest.mark.parametrize(
    ("data", "digest"),
    [
        pytest.param(
            "5a424d093100002b0000536d616c6c2066696c657320646f6e2774206765"
            "7420636f6d7072657373656420617420616c6c2e2e2e0a060000000000",
            "8c929efb5fd28b5b82385b67b408f5e775a4756d7cc6373eebddb8668343ad40",
            id="uncompressed",
        ),
        pytest.param(
            "5a424d092d0000a0000018000018000018000061616161616161617835ef"
            "340f0000f10f00000000000000000000000000060000000000",
            "ef56118ff333a8bfeffc346c4987a1a178762570b3eb1d704a2c1e9b3a877561",
            id="small",
        ),
        pytest.param(
            "5a424d09d80100df36002301005001007601004c6f72656d20697073756d"
            "20646f6c6f722073742061657420636e7365636574757220616469706973"
            "696e67656c69742e517573716566617563627520657820736170656e7661"
            "6570656c6c6e6573656d6c61637261496e20696475727573206d69707269"
            "74656c757364206f76616c7354656d7075206c656f7561656e6561646469"
            "6d206e2074656d706f72506c6e7276697675736672696c61206c636e636d"
            "657473626962656e64756d67657461732e496c696d6173206e6c6d616c75"
            "64616c696e616e746567726e6e63707365722e5574206864726572697473"
            "6d7072766c637373207074656e74747469736f6f73712e41646c696f7261"
            "6f7175657465727562696f74726370746f686d6f732e0a0a4c0d2c341b41"
            "3e26113c5f6e805b6b7c65529d967ec4b310edb922ca7b1deca5faf4434a"
            "fbfa52fb8272b2ffb7016f7fcbc1b9f1373af99e3eb4e94fa9b3bafe39d3"
            "6959add6f36b55eecdb59d2ec3d1d029fc0055a9cbed016111718114103f"
            "480147110116011040f125f3ffffffffffffffffffffffffffffffffffff"
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            "ffffffffffffffff1f002cf68f57d9c576d73bfd7cd3d756000006000000"
            "0000",
            "73d3dd96ca2e2f0144a117019256d770ee7c6febeaee09b24956c723ae22b529",
            id="large",
        ),
    ],
)
def test_lzbitmap_decompress(data: str, digest: str) -> None:
    assert hashlib.sha256(lzbitmap.decompress(bytes.fromhex(data))).hexdigest() == digest


@pytest.mark.benchmark
def test_benchmark_lzbitmap_decompress(benchmark: BenchmarkFixture) -> None:
    buf = bytes.fromhex(
        "5a424d092d0000a0000018000018000018000061616161616161617835ef"
        "340f0000f10f00000000000000000000000000060000000000",
    )
    assert benchmark(lzbitmap.decompress, buf) == b"a" * 158 + b"xa"


@pytest.mark.benchmark
def test_benchmark_large_lzbitmap_decompress(benchmark: BenchmarkFixture) -> None:
    buf = bytes.fromhex(
        "5a424d09d80100df36002301005001007601004c6f72656d20697073756d"
        "20646f6c6f722073742061657420636e7365636574757220616469706973"
        "696e67656c69742e517573716566617563627520657820736170656e7661"
        "6570656c6c6e6573656d6c61637261496e20696475727573206d69707269"
        "74656c757364206f76616c7354656d7075206c656f7561656e6561646469"
        "6d206e2074656d706f72506c6e7276697675736672696c61206c636e636d"
        "657473626962656e64756d67657461732e496c696d6173206e6c6d616c75"
        "64616c696e616e746567726e6e63707365722e5574206864726572697473"
        "6d7072766c637373207074656e74747469736f6f73712e41646c696f7261"
        "6f7175657465727562696f74726370746f686d6f732e0a0a4c0d2c341b41"
        "3e26113c5f6e805b6b7c65529d967ec4b310edb922ca7b1deca5faf4434a"
        "fbfa52fb8272b2ffb7016f7fcbc1b9f1373af99e3eb4e94fa9b3bafe39d3"
        "6959add6f36b55eecdb59d2ec3d1d029fc0055a9cbed016111718114103f"
        "480147110116011040f125f3ffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffff1f002cf68f57d9c576d73bfd7cd3d756000006000000"
        "0000",
    )
    assert (
        hashlib.sha256(benchmark(lzbitmap.decompress, buf)).hexdigest()
        == "73d3dd96ca2e2f0144a117019256d770ee7c6febeaee09b24956c723ae22b529"
    )
