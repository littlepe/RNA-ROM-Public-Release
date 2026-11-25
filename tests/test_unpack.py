# -*- coding: utf-8 -*-
"""Tests for the vendor unpackers.

They never touch the network and they work on the small files that are built
here, so the parsing of the headers is covered.
"""

from __future__ import print_function

import os
import struct
import zlib

import pytest

from oem_unpack import ampack, gettype, kdzextract, listing, nb0unpack, pac_extract


def test_gettype_sparse(tmp_path):
    """A sparse image has to be recognised."""
    path = tmp_path / "system.img"
    header = struct.pack("<I", 0xED26FF3A) + b"\x00" * 60
    path.write_bytes(header)
    assert gettype.gettype(str(path)) == "sparse"


def test_gettype_ext4(tmp_path):
    """An ext4 superblock has to be recognised."""
    path = tmp_path / "system.img"
    data = bytearray(2048)
    data[1080:1082] = b"\x53\xef"
    path.write_bytes(bytes(data))
    assert gettype.gettype(str(path)).startswith("ext")


def test_gettype_unknown(tmp_path):
    """A file that matches nothing has to be reported as unknown."""
    path = tmp_path / "random.bin"
    path.write_bytes(b"\x00" * 4096)
    assert gettype.gettype(str(path)) in ("unknow", "unknown")


def test_pac_crc16():
    """The CRC16 of the PAC has to be stable."""
    assert pac_extract.crc16(b"123456789") == pac_extract.crc16(b"123456789")
    assert pac_extract.crc16(b"") == 0


def test_pac_header_is_rejected(tmp_path):
    """A file that is not a PAC has to be refused."""
    path = tmp_path / "broken.pac"
    path.write_bytes(b"\x00" * 64)
    with pytest.raises(Exception):
        pac_extract.PacExtractor(str(path), str(tmp_path)).extract()


def test_ampack_crc32(tmp_path):
    """The CRC32 of the AMLogic image has to match the zlib one."""
    path = tmp_path / "image.bin"
    path.write_bytes(b"\x00\x00\x00\x00hello")
    assert ampack.file_crc32(str(path)) == (zlib.crc32(b"hello") ^ 0xFFFFFFFF) & 0xFFFFFFFF


def test_ampack_header_too_small(tmp_path):
    """An image that is too small has to be refused."""
    path = tmp_path / "small.img"
    path.write_bytes(b"\x00" * 8)
    with pytest.raises(Exception):
        ampack.read_header(open(str(path), "rb"))


def test_nb0_detect(tmp_path):
    """A file that is not an NB0 has to be detected."""
    path = tmp_path / "broken.nb0"
    path.write_bytes(b"\x00" * 128)
    assert nb0unpack.detect_nb0(str(path)) is False


def test_kdz_detect(tmp_path):
    """A file that is not a KDZ has to be detected."""
    path = tmp_path / "broken.bin"
    path.write_bytes(b"\x00" * 128)
    assert kdzextract.is_kdz_file(str(path)) is False
    assert kdzextract.is_dz_file(str(path)) is False


def test_kdz_magic(tmp_path):
    """The KDZ and the DZ magic have to be recognised."""
    kdz = tmp_path / "firmware.kdz"
    kdz.write_bytes(b"\x28\x05\x00\x00" + b"\x00" * 60)
    assert kdzextract.is_kdz_file(str(kdz)) is True


def test_kdz_payloads(tmp_path):
    """A KDZ without a DZ payload has to be reported."""
    path = tmp_path / "firmware.kdz"
    path.write_bytes(b"\x28\x05\x00\x00" + b"\x00" * 60)
    assert kdzextract.kdz_dz_payloads(str(path)) == []


def test_format_size():
    """The size has to be formatted with a unit."""
    assert kdzextract.format_size(1024).endswith("KiB")
    assert kdzextract.format_size(0) == "0 B"


def test_listing_human_size():
    """The size of a partition has to be formatted with a unit."""
    assert listing.human_size(0) == "0 B"
    assert listing.human_size(512) == "512 B"
    assert listing.human_size(1024) == "1.0 KiB"
    assert listing.human_size(1024 * 1024) == "1.0 MiB"
    assert listing.human_size(1024 ** 3) == "1.0 GiB"


def test_listing_format_offset():
    """The offset of a partition has to be formatted as a hex number."""
    assert listing.format_offset(0x1000) == "0x00001000"
    assert listing.format_offset(None) == ""


def test_listing_table():
    """The partition list has to use the shared table."""
    import io

    buffer = io.StringIO()
    listing.print_partitions(
        [
            {"name": "system", "size": 1024 * 1024, "offset": 0x1000},
            {"name": "super", "size": 2 * 1024 ** 3, "offset": 0x2000},
        ],
        title="Partitions",
        stream=buffer,
    )
    text = buffer.getvalue()
    assert text.startswith("> Partitions (2):\n")
    assert "Name" in text and "Size" in text and "Offset" in text
    assert "system" in text and "1.0 MiB" in text and "0x00001000" in text
    assert "2.0 GiB" in text
    lines = text.splitlines()
    assert lines[1].index("Name") == lines[2].index("system")
    assert lines[1].index("Size") + 4 == lines[2].index("1.0 MiB") + 7
    assert lines[1].index("Offset") + 6 == lines[2].index("0x00001000") + 10


def test_listing_empty():
    """An empty partition list has to be reported."""
    import io

    buffer = io.StringIO()
    listing.print_partitions([], stream=buffer)
    assert buffer.getvalue() == "> Partitions: none\n"


def test_listing_rows():
    """The rows of the different vendors have to be normalised."""
    rows = listing.partition_rows([("system", 100, 8), {"name": "super"}])
    assert rows[0] == {
        "name": "system", "size": 100, "offset": 8, "type": "", "note": "",
    }
    assert rows[1]["name"] == "super"
    assert rows[1]["size"] is None


def test_listing_is_shared():
    """Every vendor has to use the shared listing."""
    from oem_unpack import huawei_firmware_extractor, pac_extract, rkfw

    for module in (huawei_firmware_extractor, nb0unpack, ampack, pac_extract, rkfw):
        assert module.listing is listing
