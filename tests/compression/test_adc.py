from __future__ import annotations

import hashlib
import io
from typing import TYPE_CHECKING

import pytest

from dissect.util.compression import adc

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture

DISSECT_ADC_COMPRESSION = "984469737365637420414443206465636f6d7072657373696f6e"
DISSECT_ADC_COMPRESSION_X4 ="994469737365637420414443206465636f6d7072657373696f6e207f00192019"

PARAMS = (
    ("data", "digest"),
    [
        pytest.param(
            DISSECT_ADC_COMPRESSION,
            "c46e20738514d290b73b16759320908f22fdb174c54b9eed36191617a55e9bc9",
            id="literal",
        ),
        pytest.param(
            DISSECT_ADC_COMPRESSION_X4,
            "d79ef73f9dff01059f5ea46434768492dd9eb39d2a83fe282a9ba86b35f6acfa",
            id="matches",
        ),
    ],
)


@pytest.mark.parametrize(*PARAMS)
def test_adc_decompress(data: str, digest: str) -> None:
    assert hashlib.sha256(adc.decompress(bytes.fromhex(data))).hexdigest() == digest


@pytest.mark.parametrize(*PARAMS)
def test_adc_decompress_stream(data: str, digest: str) -> None:
    assert hashlib.sha256(adc.decompress(io.BytesIO(bytes.fromhex(data)))).hexdigest() == digest


def test_adc_decompress_plaintext() -> None:
    assert adc.decompress(bytes.fromhex(DISSECT_ADC_COMPRESSION)) == (
        b"Dissect ADC decompression"
    )
    assert adc.decompress(bytes.fromhex(DISSECT_ADC_COMPRESSION_X4)) == (
        b"Dissect ADC decompression " * 4
    )


def test_adc_decompress_invalid_distance() -> None:
    with pytest.raises(ValueError, match="Invalid match distance in ADC stream"):
        adc.decompress(bytes.fromhex("0000"))


@pytest.mark.benchmark
@pytest.mark.parametrize(*PARAMS)
def test_benchmark_adc_decompress(data: str, digest: str, benchmark: BenchmarkFixture) -> None:
    assert hashlib.sha256(benchmark(adc.decompress, bytes.fromhex(data))).hexdigest() == digest
