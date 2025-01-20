import gzip
from pathlib import Path
from tarfile import TarFile

import pytest

from dissect.util import cpio


def absolute_path(filename: str) -> Path:
    return Path(__file__).parent / filename


def _verify_archive(archive: TarFile) -> None:
    assert sorted(archive.getnames()) == sorted(
        [f"dir/file_{i}" for i in range(1, 101)] + ["large-file", "small-file", "symlink-1", "symlink-2"]
    )

    small_file = archive.getmember("small-file")
    assert small_file.name == "small-file"
    assert small_file.size == 9
    assert small_file.isfile()
    assert (fh := archive.extractfile(small_file))
    assert fh.read() == b"contents\n"

    large_file = archive.getmember("large-file")
    assert large_file.name == "large-file"
    assert large_file.size == 0x3FC000
    assert small_file.isfile()
    assert (fh := archive.extractfile(large_file))
    assert fh.read() == b"".join([bytes([i] * 4096) for i in range(255)]) * 4

    symlink_1 = archive.getmember("symlink-1")
    assert symlink_1.issym()
    assert symlink_1.size == 0
    assert symlink_1.linkname == "small-file"

    symlink_2 = archive.getmember("symlink-2")
    assert symlink_2.issym()
    assert symlink_1.size == 0
    assert symlink_2.linkname == "dir/file_69"


@pytest.mark.parametrize(
    ("path", "format"),
    [
        ("data/bin.cpio.gz", cpio.FORMAT_CPIO_BIN),
        ("data/odc.cpio.gz", cpio.FORMAT_CPIO_ODC),
        ("data/hpbin.cpio.gz", cpio.FORMAT_CPIO_HPBIN),
        ("data/hpodc.cpio.gz", cpio.FORMAT_CPIO_HPODC),
        ("data/newc.cpio.gz", cpio.FORMAT_CPIO_NEWC),
        ("data/crc.cpio.gz", cpio.FORMAT_CPIO_CRC),
    ],
)
def test_cpio_formats(path: str, format: int) -> None:
    # With explicit format
    archive = cpio.open(absolute_path(path), format=format)
    _verify_archive(archive)

    # Autodetect format
    archive = cpio.open(absolute_path(path))
    _verify_archive(archive)

    # From fileobj using CpioFile class
    with gzip.GzipFile(absolute_path(path), "rb") as fh:
        archive = cpio.CpioFile(fileobj=fh)
        _verify_archive(archive)
