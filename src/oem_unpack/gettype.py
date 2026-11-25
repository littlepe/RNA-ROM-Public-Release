#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Image and firmware type detection.

The type is derived from the magic bytes, the extension and the layout of the
file (sparse, ext, erofs, super, ...) and the compression format is
recognised as well.
"""

from __future__ import print_function

import os
import struct

try:
    from fs.lpunpack import ReadMetadata
except Exception:
    ReadMetadata = None

LP_METADATA_GEOMETRY_MAGIC = 1634485351
LP_METADATA_HEADER_MAGIC = 1095520304


def CHECK_SPARSE_INFO(path):
    """Check whether the file is an Android sparse image.

    Args:
        path: The file to check.

    Returns:
        bool: True when the magic is 0xED26FF3A."""
    with open(path, "rb") as f:
        f.seek(0)
        buf = f.read(4)
    return buf == b":\xff&\xed"


def CHECK_EROFS_INFO(path):
    """Check whether the file is an EROFS image.

    Args:
        path: The file to check.

    Returns:
        bool: True when the EROFS magic sits at offset 1024."""
    with open(path, "rb") as f:
        f.seek(1024)
        buf = f.read(4)
    return buf == b"\xe2\xe1\xf5\xe0"


def CHECK_EXT_INFO(path):
    """Check whether the file is an ext filesystem image.

    Args:
        path: The file to check.

    Returns:
        bool: True when the ext superblock magic sits at offset 1080."""
    with open(path, "rb") as f:
        f.seek(1080)
        buf = f.read(2)
    return buf == b"S\xef"


def CHECK_F2FS_INFO(path):
    """Check whether the file is an F2FS image.

    Args:
        path: The file to check.

    Returns:
        bool: True when the F2FS magic sits at offset 1024."""
    with open(path, "rb") as f:
        f.seek(1024)
        buf = f.read(4)
    return buf == b"\x10 \xf5\xf2"


def CHECK_FAT_INFO(path):
    """Check whether the file is a FAT12/FAT16/FAT32 image.

    Args:
        path: The file to check.

    Returns:
        bool: True when the boot sector and the BPB fields are valid and the volume
            type is FAT."""
    try:
        with open(path, "rb") as f:
            boot = f.read(512)
    except Exception:
        return False
    if len(boot) < 512 or boot[510:512] != b"\x55\xaa":
        return False
    if boot[0] not in (0xEB, 0xE9):
        return False
    byts_per_sec = struct.unpack_from("<H", boot, 11)[0]
    sec_per_clus = boot[13]
    rsvd_sec = struct.unpack_from("<H", boot, 14)[0]
    num_fats = boot[16]
    tot_sec = struct.unpack_from("<H", boot, 19)[0] or \
        struct.unpack_from("<I", boot, 32)[0]
    if byts_per_sec not in (512, 1024, 2048, 4096):
        return False
    if not sec_per_clus or sec_per_clus & (sec_per_clus - 1):
        return False
    if not rsvd_sec or not num_fats or not tot_sec:
        return False
    tags = boot[54:62] + boot[82:90]
    return any(tag in tags for tag in (b"FAT12", b"FAT16", b"FAT32"))


def CHECK_BOOT_INFO(path):
    """Check whether the file is an Android boot or vendor_boot image.

    Args:
        path: The file to check.

    Returns:
        bool: True when the header is ANDROID! or VNDRBOOT."""
    with open(path, "rb") as f:
        start = f.read(8)
    return start[0:8] in (b"ANDROID!", b"VNDRBOOT")


def CHECK_APP_INFO(path):
    """Check whether the file is a Huawei .app or update.bin package.

    Args:
        path: The file to check.

    Returns:
        bool: True when the extension or the header magic matches."""
    name = os.path.basename(path).lower()
    if name.endswith(".app") or name == "update.bin":
        return True
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x55\xAA\x5A\xA5"
    except Exception:
        return False


def CHECK_PAC_INFO(path):
    """Check whether the file is a Unisoc PAC package.

    Args:
        path: The file to check.

    Returns:
        bool: True for a .pac extension, a ZIP wrapper or the PAC magic."""
    name = os.path.basename(path).lower()
    if name.endswith(".pac"):
        return True
    try:
        with open(path, "rb") as f:
            header = f.read(2124)
        if len(header) < 2124:
            return False
        first_magic = struct.unpack('<I', header[:4])[0]
        # PAC wrapped in a ZIP
        if first_magic == 0x04034B50:
            return True
        pac_magic = struct.unpack('<I', header[2116:2120])[0]
        if pac_magic == 0xFFFAFFFA:
            return True
    except Exception:
        return False
    return False

_KDZ_MAGICS = (
    b"\x28\x05\x00\x00\x34\x31\x25\x80",
    b"\x18\x05\x00\x00\x32\x79\x44\x50",
    b"\x28\x05\x00\x00\x24\x38\x22\x25",
)
_DZ_MAGIC = b"\x32\x96\x18\x74"


def CHECK_KDZ_INFO(path):
    """Check whether the file is an LG KDZ package.

    Args:
        path: The file to check.

    Returns:
        bool: True when the extension or the header magic matches."""
    name = os.path.basename(path).lower()
    if name.endswith(".kdz"):
        return True
    try:
        with open(path, "rb") as f:
            return f.read(8) in _KDZ_MAGICS
    except Exception:
        return False


def CHECK_DZ_INFO(path):
    """Check whether the file is an LG DZ partition package.

    Args:
        path: The file to check.

    Returns:
        bool: True when the extension or the header magic matches."""
    name = os.path.basename(path).lower()
    if name.endswith(".dz") and not name.endswith(".kdz"):
        return True
    try:
        with open(path, "rb") as f:
            return f.read(4) == _DZ_MAGIC
    except Exception:
        return False


def CHECK_AVB_INFO(path):
    """Check whether the file is an AVB vbmeta image.

    Args:
        path: The file to check.

    Returns:
        bool: True when the header is AVB0."""
    with open(path, "rb") as f:
        start = f.read(4)
    return start[0:4] == b"AVB0"


def CHECK_DTBO_INFO(path):
    """Check whether the file is a DTBO image.

    Args:
        path: The file to check.

    Returns:
        bool: True when the header holds the DTBO magic."""
    with open(path, "rb") as f:
        magic = f.read(4)
    return magic == b"\xd7\xb7\xab\x1e"


def CHECK_DTB_INFO(path):
    """Check whether the file is a Device Tree Blob.

    Args:
        path: The file to check.

    Returns:
        bool: True when the header holds the DTB magic."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\xd0\x0d\xfe\xed"
    except Exception:
        return False


def CHECK_SIN_INFO(path):
    """Check whether the file is a Sony SIN image.

    Args:
        path: The file to check.

    Returns:
        bool: True when the extension or the header carries the SIN marker."""
    name = os.path.basename(path).lower()
    if name.endswith(".sin"):
        return True
    try:
        with open(path, "rb") as f:
            buf = f.read(64)
    except Exception:
        return False
    return buf.startswith(b"SIN") or b"SIN" in buf[:32]


def CHECK_ELF_INFO(path):
    """Check whether the file is an ELF file.

    Args:
        path: The file to check.

    Returns:
        bool: True when the header is 7F 45 4C 46."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except Exception:
        return False


def CHECK_CPIO_INFO(path):
    """Check whether the file is an uncompressed CPIO archive.

    Args:
        path: The file to check.

    Returns:
        bool: True when the header is one of 070701/070702/070707."""
    try:
        with open(path, "rb") as f:
            magic = f.read(6)
    except Exception:
        return False
    return magic in (b"070701", b"070702", b"070707")


def _cpio_name_hint(path):
    """Guess from the file name whether this looks like a ramdisk or CPIO.

    Args:
        path: The file to check.

    Returns:
        bool: True when the name holds cpio/ramdisk/initrd/initramfs."""
    name = os.path.basename(path).lower()
    return (
        ".cpio" in name
        or "ramdisk" in name
        or name.startswith("initrd")
        or "initramfs" in name
    )


def CHECK_RAMDISK_INFO(path):
    """Use the file name as a hint to decide whether this is a ramdisk or CPIO.

    Args:
        path: The file to check.

    Returns:
        bool: True when the name looks like a ramdisk and the file is CPIO or a
            known compressed stream."""
    if not _cpio_name_hint(path):
        return False
    if CHECK_CPIO_INFO(path):
        return True
    return decompres(path) != "raw"


def CHECK_SUPER_INFO(path):
    """Check whether the file is an Android super (LP) dynamic partition image.

    Args:
        path: The file to check.

    Returns:
        bool: True when the LP geometry and the header magic both match."""
    if ReadMetadata is None:
        with open(path, "rb") as f:
            f.seek(4096)
            geo = f.read(8)
        try:
            magic = struct.unpack_from("<I", geo, 0)[0]
        except Exception:
            return False
        return magic == LP_METADATA_GEOMETRY_MAGIC
    try:
        in_file_fd = open(path, "rb")
        metadata = ReadMetadata(in_file_fd)
        in_file_fd.close()
        header = metadata.header
        geometry = metadata.geometry
        if geometry.magic != LP_METADATA_GEOMETRY_MAGIC:
            return False
        if header.magic != LP_METADATA_HEADER_MAGIC:
            return False
        return True
    except Exception:
        return False


def gettype(path):
    """Detect the type of an image or firmware file.

    KDZ, DZ, PAC, sparse, filesystems and boot images are matched in that
    order.

    Args:
        path: The file to identify.

    Returns:
        str: The type name (kdz/ext/fat/sparse/super), ``unknow`` when it cannot be
            told."""
    image_type = "unknow"
    try:
        if CHECK_KDZ_INFO(path):
            image_type = "kdz"
        elif CHECK_DZ_INFO(path):
            image_type = "dz"
        elif CHECK_PAC_INFO(path):
            image_type = "pac"
        elif CHECK_SPARSE_INFO(path):
            image_type = "sparse"
        elif CHECK_EXT_INFO(path):
            image_type = "ext"
        elif CHECK_EROFS_INFO(path):
            image_type = "erofs"
        elif CHECK_SUPER_INFO(path):
            image_type = "super"
        elif CHECK_F2FS_INFO(path):
            image_type = "f2fs"
        elif CHECK_FAT_INFO(path):
            image_type = "fat"
        elif CHECK_BOOT_INFO(path):
            image_type = "kernel"
        elif CHECK_DTBO_INFO(path):
            image_type = "dtbo"
        elif CHECK_DTB_INFO(path):
            image_type = "dtb"
        elif CHECK_SIN_INFO(path):
            image_type = "sin"
        elif CHECK_ELF_INFO(path):
            image_type = "elf"
        elif CHECK_CPIO_INFO(path) or CHECK_RAMDISK_INFO(path):
            image_type = "cpio"
        elif CHECK_APP_INFO(path):
            image_type = "app"
        elif CHECK_AVB_INFO(path):
            image_type = "vbmeta"
    except Exception:
        image_type = "unknow"
    return image_type


def image_data_size(path):
    """Compute the logical size of an image.

    A sparse image is counted as blocks times block size, every other file
    reports its size on disk.

    Args:
        path: The image path.

    Returns:
        int: The logical size in bytes, 0 when the file is missing or cannot be
            read."""
    if not path or not os.path.isfile(path):
        return 0
    try:
        with open(path, "rb") as f:
            hdr = f.read(28)
        if len(hdr) >= 28:
            magic, _maj, _min, _fhs, _chs, blk_sz, total_blks, _chunks, _cksum = struct.unpack("<I4H4I", hdr)
            if magic == 0xED26FF3A and blk_sz and total_blks:
                return int(total_blks) * int(blk_sz)
    except Exception:
        pass
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def decompres(filename):
    """Detect the compression format from the file header.

    Args:
        filename: The file to identify.

    Returns:
        str: The format (gzip/lz4/lz4_legacy/lzop/bzip2/xz/lzma/zstd), raw when
            the file is not compressed."""
    with open(filename, "rb") as f:
        start = f.read(8)
    if start.startswith(b"\x1f\x8b"):
        file_type = "gzip"
    elif start.startswith(b"\x02!L\x18"):
        file_type = "lz4_legacy"
    elif start.startswith(b"\x03!L\x18") or start.startswith(b'\x04"M\x18'):
        file_type = "lz4"
    elif start.startswith(b"\x89LZO"):
        file_type = "lzop"
    elif start.startswith(b"BZh"):
        file_type = "bzip2"
    elif start.startswith(b"]\x00\x00\x80") or start.startswith(b"\xfd7zXZ"):
        file_type = "xz"
    elif start.startswith(b"]\x00\x00"):
        file_type = "lzma"
    elif start.startswith(b"\x28\xb5\x2f\xfd"):
        file_type = "zstd"
    else:
        file_type = "raw"
    return file_type
