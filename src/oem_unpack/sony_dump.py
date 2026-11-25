#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unpack Sony Xperia firmware, a pure Python version of sony_dump.

It handles Android boot.img, Sony SIN v1-v5, ELF kernels and tar or sparse
images and writes the raw partition images, the logic matches the C version
of sony_dump. Only the standard library is used, LZ4 goes through the lz4
module when it is there and falls back to a pure Python block decompression."""

from __future__ import print_function

import gzip
import os
import struct
import sys

SPARSE_MAGIC = 0xED26FF3A
CHUNK_TYPE_RAW = 0xCAC1
CHUNK_TYPE_FILL = 0xCAC2
CHUNK_TYPE_DONT_CARE = 0xCAC3
CHUNK_TYPE_CRC32 = 0xCAC4
CHUNK_TYPE_LZ4 = 0xCAC5

IS_BE = (sys.byteorder == "big")


# --------------------------------------------------------------------------
# LZ4 block decompression
# --------------------------------------------------------------------------
try:
    from lz4.block import decompress as _lz4_block
except Exception:
    _lz4_block = None


def _lz4_block_py(src, dst_size):
    """An LZ4 block decompression in pure Python.

        The same as ``LZ4_decompress_safe``.

    Args:
        src: The compressed bytes.
        dst_size: The size after decompression.

    Returns:
        bytes: The decompressed data.

    Raises:
        ValueError: When the offset is invalid."""
    dst = bytearray(max(dst_size, 1))
    n = len(src)
    si = 0
    di = 0
    while si < n:
        token = src[si]
        si += 1
        lit = token >> 4
        if lit == 15:
            while si < n:
                b = src[si]
                si += 1
                lit += b
                if b != 255:
                    break
        if lit:
            dst[di:di + lit] = src[si:si + lit]
            di += lit
            si += lit
        if si >= n:
            break
        if si + 2 > n:
            break
        offset = src[si] | (src[si + 1] << 8)
        si += 2
        match = token & 0x0F
        if match == 15:
            while si < n:
                b = src[si]
                si += 1
                match += b
                if b != 255:
                    break
        match += 4
        start = di - offset
        if start < 0:
            raise ValueError("lz4: bad offset")
        for k in range(match):
            dst[di] = dst[start + k]
            di += 1
    return bytes(dst[:di])


def lz4_decompress_safe(src, dst_size):
    """Decompress one LZ4 block.

    The ``lz4`` module is used when it is there, otherwise the pure Python
    implementation does the work.

    Args:
        src: The compressed bytes.
        dst_size: The size after decompression.

    Returns:
        bytes: The decompressed data."""
    if _lz4_block is not None:
        try:
            return _lz4_block(bytes(src), uncompressed_size=dst_size)
        except Exception:
            pass
    return _lz4_block_py(bytes(src), dst_size)


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def _basename(path):
    """Take the last part of a path.

    Args:
        path: The path.

    Returns:
        str: The file name."""
    path = str(path).replace("\\", "/")
    return path.rsplit("/", 1)[-1]


def _le32(b):
    """Read a little endian 32 bit integer.

    Args:
        b: Four bytes.

    Returns:
        int: The value."""
    return b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)


def _le64(b):
    """Read a little endian 64 bit integer.

    Args:
        b: Eight bytes.

    Returns:
        int: The value."""
    return int.from_bytes(b, "little")


def _read_exact(f, n):
    """Read exactly n bytes.

    Args:
        f: The binary stream.
        n: The number of bytes to read.

    Returns:
        bytes: The data that was read.

    Raises:
        EOFError: When the end of the file comes first."""
    data = f.read(n)
    if len(data) != n:
        raise EOFError("short read: want %d got %d" % (n, len(data)))
    return data


def _be32(b):
    """Read a big endian 32 bit integer.

    Args:
        b: The bytes.

    Returns:
        int: The value."""
    return int.from_bytes(b, "big")


def _be64(b):
    """Read a big endian 64 bit integer.

    Args:
        b: The bytes.

    Returns:
        int: The value."""
    return int.from_bytes(b, "big")


# --------------------------------------------------------------------------
# SIN v1/v2/v3 -> raw
# --------------------------------------------------------------------------
def convert_sin_to_elf(filein, fileout):
    """Turn a SIN into a raw image.

    Args:
        filein: The path of the SIN.
        fileout: The path of the image to write.

    Returns:
        int: The file type (2=ELF, 3=EXT4, 0=unknown), -1 on failure."""
    sin = open(filein, "rb")
    try:
        sin.seek(0, os.SEEK_END)
        sin_sz = sin.tell()
        sin.seek(0)
        if sin_sz < 1024:
            print("Error: is %s valid?" % filein)
            return -1
        header = _read_exact(sin, 1024)

        sin_version = 0
        if header[0:1] == b"\x01":
            sin_version = 1
        elif header[0:1] == b"\x02":
            sin_version = 2
        elif header[0:1] == b"\x03":
            sin_version = 3
        print("Proccessing %s..." % filein)
        if sin_version > 3 or sin_version == 0:
            print("Error: found unsupported sin version: %d!!!" % sin_version)
            return -1
        if sin_version == 3 and header[0:4] != b"\x03\x53\x49\x4E":
            print("Error: file is not a sin!?")
            return -1

        print("Sin version: %d" % sin_version)
        print("File size: 0x%X" % sin_sz)

        if sin_version < 3:
            sin_header_sz = _be32(header[2:6])
            sin_data_sz = sin_sz - (sin_header_sz + 16)
        else:
            sin_header_sz = _be32(header[4:8])
            sin_data_sz = _be32(header[0x18:0x1C])

        print("Sin header size: 0x%X" % sin_header_sz)
        print("Sin data size: 0x%X" % sin_data_sz)
        if sin_header_sz < 1 or sin_data_sz < 1:
            print("Error: sin header size or sin data size is 0!")
            return -1
        if sin_version < 3:
            sin_header_sz += 16

        sin.seek(sin_header_sz)
        mmcf_header = _read_exact(sin, 8)
        mmcf_magic = mmcf_header[0:4]
        gptp_len = _be32(mmcf_header[4:8])

        sin_data_first_sz = 0
        file_type = 0
        ext4_file_size = 0

        if mmcf_magic == b"MMCF":
            print("Found MMCF magic string!")
            non_loader = 1
            if gptp_len:
                print("GPTP len: 0x%x" % gptp_len)
                mmcf_data = _read_exact(sin, 24)
                print("GPTP_UUID: %s" % _uuid_str(mmcf_data[8:24]))
                file_type, ext4_file_size = _convert_mmcf(
                    sin, fileout, sin_header_sz, gptp_len, mmcf_data)
                if file_type < 0:
                    return -1
                print("Extracting...")
                print("%s extracted." % fileout)
                return file_type
        elif mmcf_magic == b"\x7fELF":
            print("Loader?")
            file_type = 2
            non_loader = 0
        elif sin_header_sz + sin_data_sz != sin_sz:
            print("No MMCF. Need to calculate data size.")
            non_loader = 1
        elif sin_header_sz + sin_data_sz == sin_sz:
            print("No MMCF. Size calc no need.")
            non_loader = 0
        else:
            print("Error: sorry I am unable to calculate sin data size!")
            return -1

        if non_loader:
            print("Calculating sin data size...")
            sin_data_first_sz += sin_data_sz
            sin_data_sz = sin_sz - sin_header_sz - sin_data_sz
            print("New sin data size: 0x%X" % sin_data_sz)

        if sin_header_sz + sin_data_sz + sin_data_first_sz != sin_sz:
            print("Sin file verification failed!")
            return -1

        print("Sin file verification ok.")
        print("Extracting...")
        _copy_range(sin, sin_header_sz + sin_data_first_sz, sin_data_sz, fileout)
        print("%s extracted." % fileout)
        return file_type
    finally:
        sin.close()


def _uuid_str(raw):
    """Format a 16 byte UUID as a string with dashes.

    Args:
        raw: The 16 bytes.

    Returns:
        str: Text such as ``xxxxxxxx-xxxx-...``."""
    out = []
    for i in range(16):
        out.append("%02x" % (raw[i] & 0xFF))
        if i in (3, 5, 7, 9):
            out.append("-")
    return "".join(out)


def _convert_mmcf(sin, fileout, sin_header_sz, gptp_len, mmcf_data):
    """Walk the GPTP area and rebuild the raw image from the LZ4A and ADDR
    segments.

        Args:
            sin: The SIN file that was located.
            fileout: The path of the image to write.
            sin_header_sz: The size of the SIN header.
            gptp_len: The length of the GPTP area.
            mmcf_data: The MMCF data.

        Returns:
            tuple: (file type, size of the ext4)."""
    out = open(fileout, "wb")
    parts = 0
    file_type = 0
    ext4_file_size = 0
    out_next_poss = 0
    t = 0
    base = sin_header_sz + gptp_len + 8
    try:
        while t < (gptp_len - len(mmcf_data)):
            dt_bytes = sin.read(4)
            if len(dt_bytes) < 4:
                break
            revert_sin_poss = sin.tell() - 4
            if dt_bytes == b"LZ4A":
                parts += 1
                print("Extracting part %d type: LZ4A" % parts)
                header_size = _be32(_read_exact(sin, 4))
                packed_off = _be64(_read_exact(sin, 8))
                unpacked_size = _be64(_read_exact(sin, 8))
                packed_size = _be64(_read_exact(sin, 8))
                unpacked_off = _be64(_read_exact(sin, 8))
                print("|-- packed data offset: 0x%x" % packed_off)
                print("|-- unpacked data size: 0x%x" % unpacked_size)
                print("|-- packed data size: 0x%x" % packed_size)
                print("|-- unpacked data offset: 0x%x" % unpacked_off)
                out_next_poss = _fill_ff(out, out_next_poss, unpacked_off)
                sin.seek(base + packed_off)
                packed = _read_exact(sin, packed_size)
                data = lz4_decompress_safe(packed, unpacked_size)
                out.write(data)
                out_next_poss = out.tell()
                print("|------ successfully decompressed part %d data." % parts)
                if parts == 1:
                    file_type, ext4_file_size = _detect_type(data)
                sin.seek(revert_sin_poss + header_size)
                step = header_size
            elif dt_bytes == b"ADDR":
                parts += 1
                print("Extracting part %d type: ADDR" % parts)
                header_size = _be32(_read_exact(sin, 4))
                packed_off = _be64(_read_exact(sin, 8))
                packed_size = _be64(_read_exact(sin, 8))
                unpacked_off = _be64(_read_exact(sin, 8))
                print("|-- packed data offset: 0x%x" % packed_off)
                print("|-- packed data size: 0x%x" % packed_size)
                print("|-- unpacked data offset: 0x%x" % unpacked_off)
                out_next_poss = _fill_ff(out, out_next_poss, unpacked_off)
                sin.seek(base + packed_off)
                data = _read_exact(sin, packed_size)
                out.write(data)
                out_next_poss = out.tell()
                print("|------ successfully extracted part %d data." % parts)
                if parts == 1:
                    file_type, ext4_file_size = _detect_type(data)
                sin.seek(revert_sin_poss + header_size)
                step = header_size
            else:
                print("t=%x Unknown part type!" % t)
                return -1, 0
            t += step if step else 1

        if ext4_file_size:
            g = out.tell()
            if g < ext4_file_size:
                print("finishing...")
                print("|--- fill 00 0x%x" % (ext4_file_size - g))
                out.write(b"\x00" * (ext4_file_size - g))
        print("|--- now out poss: 0x%x" % out.tell())
        return file_type, ext4_file_size
    finally:
        out.close()


def _fill_ff(out, out_next_poss, target):
    """Fill with 0xFF up to the target position.

    Args:
        out: The output file object.
        out_next_poss: The current write position.
        target: The target position.

    Returns:
        int: The position after the fill."""
    if out_next_poss < target:
        print("|------ fill 0xFF: 0x%x" % (target - out_next_poss))
        out.write(b"\xff" * (target - out_next_poss))
    return out.tell()


def _detect_type(data):
    """Detect the type of the image (ELF or EXT4).

    Args:
        data: The image data.

    Returns:
        tuple: (file type, size of the ext4)."""
    limit = len(data) - 4
    for gg in range(max(0, limit)):
        if data[gg:gg + 4] == b"\x7fELF" and gg == 0:
            print("|------ Filetype ELF.")
            return 2, 0
        if data[gg:gg + 2] == b"\x53\xef":
            size = _le64(data[gg - 52:gg - 52 + 8]) * 4096
            print("|------ Found ext4 magic. Ext4 size: 0x%x" % size)
            return 3, size
    return 0, 0


def _copy_range(src, offset, size, dst):
    """Copy a range of the source stream to the target file.

    Args:
        src: The source binary stream.
        offset: The start offset.
        size: The number of bytes to copy.
        dst: The path of the target file."""
    src.seek(offset)
    with open(dst, "wb") as out:
        remain = size
        while remain > 0:
            data = src.read(min(remain, 4 * 1024 * 1024))
            if not data:
                break
            out.write(data)
            remain -= len(data)


# --------------------------------------------------------------------------
# ELF kernel sections
# --------------------------------------------------------------------------
def extract_elf(dest, inp):
    """Extract the sections with the ELF program headers.

    Args:
        dest: The output directory.
        inp: The path of the ELF.

    Returns:
        int: 0 on success, 1 on failure."""
    with open(inp, "rb") as fi:
        head = fi.read(6)
        if len(head) < 6:
            print("unable to open %s" % inp)
            return 1
        determined = head[4]

        if determined == 2:
            fi.seek(0)
            ehdr = _read_exact(fi, 64)
            if ehdr[0:4] != b"\x7fELF":
                print("ELF magic not found, exiting")
                return 1
            e_entry, e_phoff = _le64(ehdr[24:32]), _le64(ehdr[32:40])
            e_phnum = int.from_bytes(ehdr[56:58], "little")
            print("ELF magic found")
            print("Entry point          : 0x%08X" % e_entry)
            print("Class                : 64-bit objects")
            print("Program Header start : 0x%x" % e_phoff)
            print("Program Header count : %d" % e_phnum)
            fi.seek(e_phoff)
            phdrs = []
            for i in range(e_phnum):
                ph = _read_exact(fi, 56)
                p_type = int.from_bytes(ph[0:4], "little")
                p_offset = _le64(ph[8:16])
                p_paddr = _le64(ph[24:32])
                p_filesz = _le64(ph[32:40])
                phdrs.append((p_offset, p_paddr, p_filesz))
            _touch_base(dest, e_entry & 0xF0000000, 64)
        else:
            fi.seek(0)
            ehdr = _read_exact(fi, 52)
            if ehdr[0:4] != b"\x7fELF":
                print("ELF magic not found, exiting")
                return 1
            e_entry, e_phoff = _le32(ehdr[24:28]), _le32(ehdr[28:32])
            e_phnum = int.from_bytes(ehdr[44:46], "little")
            print("ELF magic found")
            print("Entry point          : 0x%08X" % e_entry)
            print("Class                : 32-bit objects")
            print("Program Header start : 0x%x" % e_phoff)
            print("Program Header count : %d" % e_phnum)
            fi.seek(e_phoff)
            phdrs = []
            for i in range(e_phnum):
                ph = _read_exact(fi, 32)
                p_offset = _le32(ph[4:8])
                p_paddr = _le32(ph[12:16])
                p_filesz = _le32(ph[16:20])
                phdrs.append((p_offset, p_paddr, p_filesz))
            _touch_base(dest, e_entry & 0xF0000000, 32)

        names = {
            0: ("boot.img-zImage", "boot.img-kerneloff"),
            1: ("boot.img-ramdisk.gz", "boot.img-ramdiskoff"),
            2: ("boot.img-dt", "boot.img-tagsoff"),
            3: ("certificate", "certificateoff"),
        }
        last_address = 0
        for idx, (p_offset, p_paddr, p_filesz) in enumerate(phdrs):
            fname, offname = names.get(idx, ("unknown.%d.bin" % idx, "unknown.%d.off" % idx))
            fpath = os.path.join(dest, fname)
            opath = os.path.join(dest, offname)
            print("%d. Dumping %s" % (idx, fpath))
            fi.seek(p_offset)
            data = _read_exact(fi, p_filesz)
            with open(fpath, "wb") as fo:
                fo.write(data)
            with open(opath, "w") as fooff:
                fooff.write("%08x\n" % p_paddr)
            last_address = p_offset + p_filesz + 8

        print("   Seeking to cmdline address = 0x%08X" % last_address)
        cmdfile = os.path.join(dest, "boot.img-cmdline")
        with open(cmdfile, "wb") as fo:
            fi.seek(last_address)
            cmd = b""
            while True:
                ch = fi.read(1)
                if not ch:
                    break
                fo.write(ch)
                cmd += ch
                if ch == b"\x00":
                    break
    return 0


def _touch_base(dest, base, _cls):
    """Write the boot.img-base file.

    Args:
        dest: The output directory.
        base: The base address.
        _cls: The width of the ELF (32 or 64 bits)."""
    with open(os.path.join(dest, "boot.img-base"), "w") as f:
        if _cls == 64:
            f.write("%08x\n" % base)
        else:
            f.write("%08x\n" % base)


# --------------------------------------------------------------------------
# Android boot.img
# --------------------------------------------------------------------------
def dump_boot(filein, fileout):
    """Parse an Android boot.img and extract its sections.

    Args:
        filein: The path of the boot.img.
        fileout: The output directory.

    Returns:
        int: 0 on success, 1 when the magic was not found."""
    with open(filein, "rb") as f:
        header = _find_boot_header(f)
        if header is None:
            print("Android boot magic not found.")
            return 1
        (kernel_size, kernel_addr, ramdisk_size, ramdisk_addr, second_size,
         second_addr, tags_addr, page_size, dt_size, os_version, name, cmdline) = header

        base = kernel_addr - 0x00008000
        print("BOARD_KERNEL_CMDLINE %s" % cmdline.decode("latin1", "replace").split("\x00")[0])
        print("BOARD_KERNEL_BASE %08x" % base)
        print("BOARD_NAME %s" % name.decode("latin1", "replace").split("\x00")[0])
        print("BOARD_PAGE_SIZE %d" % page_size)
        print("BOARD_KERNEL_OFFSET %08x" % (kernel_addr - base))
        print("BOARD_RAMDISK_OFFSET %08x" % (ramdisk_addr - base))
        if second_size:
            print("BOARD_SECOND_OFFSET %08x" % (second_addr - base))
        print("BOARD_TAGS_OFFSET %08x" % (tags_addr - base))
        a = b = c = y = m = 0
        if os_version:
            ver = os_version >> 11
            lvl = os_version & 0x7FF
            a = (ver >> 14) & 0x7F
            b = (ver >> 7) & 0x7F
            c = ver & 0x7F
            y = (lvl >> 4) + 2000
            m = lvl & 0xF
            print("BOARD_OS_VERSION %d.%d.%d" % (a, b, c))
            print("BOARD_OS_PATCH_LEVEL %d-%02d" % (y, m))
        if dt_size:
            print("BOARD_DT_SIZE %d" % dt_size)

        stem = os.path.join(fileout, _basename(filein))
        _write_str(stem + "-cmdline", cmdline.decode("latin1", "replace").split("\x00")[0])
        _write_str(stem + "-board", name.decode("latin1", "replace").split("\x00")[0])
        _write_str(stem + "-base", "%08x" % base)
        _write_str(stem + "-pagesize", "%d" % page_size)
        _write_str(stem + "-kerneloff", "%08x" % (kernel_addr - base))
        _write_str(stem + "-ramdiskoff", "%08x" % (ramdisk_addr - base))
        if second_size:
            _write_str(stem + "-secondoff", "%08x" % (second_addr - base))
        _write_str(stem + "-tagsoff", "%08x" % (tags_addr - base))
        if os_version:
            _write_str(stem + "-osversion", "%d.%d.%d" % (a, b, c))
            _write_str(stem + "-oslevel", "%d-%02d" % (y, m))

        _dump_region(f, stem + "-zImage", kernel_size, page_size)
        _dump_region(f, stem + "-ramdisk.gz", ramdisk_size, page_size)
        if second_size:
            _dump_region(f, stem + "-second", second_size, page_size)
            _align(f, second_size, page_size)
        if dt_size:
            _dump_region(f, stem + "-dtb", dt_size, page_size)
    return 0


def _find_boot_header(f):
    """Look for the Android boot header in the first 4KiB.

    Args:
        f: The binary stream.

    Returns:
        tuple: The fields of the boot header, None when it was not found."""
    for i in range(0, 4097):
        f.seek(i)
        if f.read(8) == b"ANDROID!":
            if i > 0:
                print("Android magic found at: %d" % i)
            f.seek(i)
            hdr = _read_exact(f, 1632)
            kernel_size = _le32(hdr[8:12])
            kernel_addr = _le32(hdr[12:16])
            ramdisk_size = _le32(hdr[16:20])
            ramdisk_addr = _le32(hdr[20:24])
            second_size = _le32(hdr[24:28])
            second_addr = _le32(hdr[28:32])
            tags_addr = _le32(hdr[32:36])
            page_size = _le32(hdr[36:40])
            dt_size = _le32(hdr[40:44])
            os_version = _le32(hdr[44:48])
            name = hdr[48:64]
            cmdline = hdr[64:576]
            return (kernel_size, kernel_addr, ramdisk_size, ramdisk_addr, second_size,
                    second_addr, tags_addr, page_size, dt_size, os_version, name, cmdline)
    return None


def _dump_region(f, path, size, page_size):
    """Read a block from the stream, write it to the file and align to the page
    afterwards.

        Args:
            f: The source binary stream.
            path: The path of the output file.
            size: The number of bytes to read.
            page_size: The size of a page.

        Returns:
            bytes: The data that was read."""
    data = f.read(size) if size > 0 else b""
    with open(path, "wb") as out:
        out.write(data)
    _align(f, size, page_size)
    return data


def _align(f, size, page_size):
    """Skip the padding, the page size decides the alignment.

    Args:
        f: The binary stream.
        size: The real length.
        page_size: The size of a page, it is not used when it is not valid."""
    if page_size <= 0:
        return
    pad = (page_size - (size % page_size)) % page_size
    if pad:
        f.seek(pad, os.SEEK_CUR)


def _write_str(path, text):
    """Write the text to a file with latin1 and add a newline.

    Args:
        path: The path of the output file.
        text: The text to write."""
    with open(path, "wb") as f:
        f.write(text.encode("latin1", "replace") + b"\n")


# --------------------------------------------------------------------------
# tar / sparse
# --------------------------------------------------------------------------
def _parseoct(p):
    """Read an octal number field of a tar header.

        Args:
            p: The bytes of the field.

    Returns:
            int: The value."""
    i = 0
    n = len(p)
    k = 0
    while k < n and (p[k] < 0x30 or p[k] > 0x37):
        k += 1
        n -= 1
    while k < len(p) and 0x30 <= p[k] <= 0x37 and n > 0:
        i = i * 8 + (p[k] - 0x30)
        k += 1
        n -= 1
    return i


def _verify_checksum(p):
    """Check the checksum of a tar header.

    Args:
        p: The 512 byte tar header.

    Returns:
        bool: True when the checksum is right."""
    u = 0
    for n in range(512):
        u += 0x20 if 148 <= n <= 155 else p[n]
    return u == _parseoct(p[148:156])


def untar(a, path, outfolder):
    """Extract the files of a tar stream.

    When the sparse fragments are seen at the end they are put back together
    into an image.

    Args:
        a: The tar stream object.
        path: The path the tar came from, it is used for the names.
        outfolder: The output directory."""
    print("Extracting from %s" % path)
    i = 0
    sparse = 0
    f = None
    while True:
        chunk = 0
        buff = a.read(512)
        if len(buff) < 512:
            print("Short read on %s: expected 512, got 0x%x" % (path, len(buff)))
            return
        if buff == b"\x00" * 512:
            print("End of %s" % path)
            if sparse:
                _reconstruct_sparse(path, outfolder, i)
            return
        if not _verify_checksum(buff):
            print("Checksum failure")
            return
        filesize = _parseoct(buff[124:136])
        ftype = buff[156:157]
        if ftype in (b"1", b"2", b"3", b"4", b"5", b"6"):
            if ftype == b"5":
                filesize = 0
        else:
            stem = _basename(path[:-4])
            if i == 0:
                tmpp = os.path.join(outfolder, stem + ".crt")
            else:
                tmpp = os.path.join(outfolder, "%s.%03d" % (stem, i - 1))
            print("Extracting file %s" % tmpp)
            i += 1
            f = open(tmpp, "wb")

        while filesize > 0:
            rd = a.read(512)
            if len(rd) < 512:
                print("Short read on %s: Expected 512, got %d" % (path, len(rd)))
                if f:
                    f.close()
                return
            if chunk == 0 and rd[:4] == b"\x3a\xff\x26\xed":
                sparse = 1
            if filesize < 512:
                rd = rd[:filesize]
            if f is not None:
                f.write(rd)
            filesize -= len(rd)
            chunk += 1

        if f is not None:
            f.close()
            f = None


def _reconstruct_sparse(path, outfolder, filecount):
    """Put the .000/.001... fragments back together with the sparse header into
        an image and rename it after its type."""
    stem = _basename(path[:-4])
    out_path = os.path.join(outfolder, stem + ".bin")
    file_type = 1
    ext4_file_size = 0
    searched = False
    with open(out_path, "wb") as out:
        for j in range(0, filecount - 1):
            out.seek(0)
            part = os.path.join(outfolder, "%s.%03d" % (stem, j))
            print("Processing %s" % part)
            with open(part, "rb") as inp:
                hdr = _read_exact(inp, 28)
                magic = _le32(hdr[0:4])
                block_size = _le32(hdr[12:16])
                total_chunks = _le32(hdr[20:24])
                if magic != SPARSE_MAGIC:
                    print("Error, sparseHeader.Magic != 0xED26FF3A, got 0x%08x" % magic)
                    return
                chunk_hdr_size = int.from_bytes(hdr[10:12], "little")
                loaded = 0
                while loaded < total_chunks:
                    ch = _read_exact(inp, 12)
                    ctype = int.from_bytes(ch[0:2], "little")
                    cblocks = _le32(ch[4:8])
                    csize = _le32(ch[8:12])
                    data_in = csize - chunk_hdr_size
                    data_out = cblocks * block_size
                    if ctype == CHUNK_TYPE_RAW:
                        for _ in range(cblocks):
                            blk = _read_exact(inp, block_size)
                            out.write(blk)
                            if j == 0 and not searched:
                                file_type, ext4_file_size = _detect_sparse(
                                    blk, block_size, file_type)
                                searched = True
                    elif ctype == CHUNK_TYPE_FILL:
                        pattern = _read_exact(inp, data_in)
                        written = 0
                        while written < data_out:
                            out.write(pattern)
                            written += data_in
                    elif ctype == CHUNK_TYPE_DONT_CARE:
                        out.seek(data_out, os.SEEK_CUR)
                    elif ctype == CHUNK_TYPE_CRC32:
                        _read_exact(inp, data_in)
                    elif ctype == CHUNK_TYPE_LZ4:
                        comp = _read_exact(inp, data_in)
                        data = lz4_decompress_safe(comp, data_out)
                        out.write(data)
                        if j == 0 and not searched:
                            file_type, ext4_file_size = _detect_sparse(
                                data, block_size, file_type)
                            searched = True
                    else:
                        print("Unknown chunk type 0x%04X" % ctype)
                        return
                    loaded += 1
            os.remove(part)
            if ext4_file_size:
                g = out.tell()
                if g < ext4_file_size:
                    out.seek(ext4_file_size - 1)
                    tail = out.read(1)
                    out.seek(ext4_file_size - 1)
                    out.write(tail)
    final = {2: ".elf", 3: ".ext4", 4: ".vfat", 5: ".img"}.get(file_type)
    if final:
        dest = os.path.join(outfolder, stem + final)
        if os.path.exists(dest):
            os.remove(dest)
        os.rename(out_path, dest)
        print("%s created." % dest)
    else:
        print("%s created." % out_path)


def _detect_sparse(buf, block_size, cur):
    """Detect the type of the filesystem inside a sparse block.

    Args:
        buf: The block of data.
        block_size: The size of a block.
        cur: The type that is known so far.

    Returns:
        tuple: (file type, size of the ext4)."""
    if cur != 1:
        return cur, 0
    for gg in range(max(0, len(buf) - 4)):
        if buf[gg:gg + 4] == b"\x7fELF" and gg == 0:
            print("Filetype ELF.")
            return 2, 0
        if buf[gg:gg + 2] == b"\x53\xef":
            size = _le64(buf[gg - 52:gg - 52 + 8]) * block_size
            print("Found ext4 magic. Ext4 size: 0x%x" % size)
            return 3, size
        if buf[gg:gg + 4] == b"\xeb\x3c\x90\x4d" and gg == 0:
            print("Filetype VFAT.")
            return 4, 0
        if buf[gg:gg + 4] == b"\x41\x4e\x44\x52" and gg == 0:
            print("Filetype IMG.")
            return 5, 0
    return cur, 0


# --------------------------------------------------------------------------
# Entry points
# --------------------------------------------------------------------------
_SIN_MAGIC2 = b"\x02\x00\x00\x00"
_SIN_MAGIC1 = b"\x01\x00\x00\x00"


def run(out_arg, inp):
    """Detect the format of the input and convert it.

    It follows the main() of the C version: out_arg is a directory or the path of a
    block device.

    Args:
        out_arg: The output directory or the block device.
        inp: The path of the input file.

    Returns:
        int: The exit code."""
    if "/dev/" in out_arg:
        to_block = True
    else:
        to_block = False
        try:
            os.makedirs(out_arg, exist_ok=True)
        except OSError as exc:
            print("FAILURE to create output folder %s! %s" % (out_arg, exc))
            return 2

    with open(inp, "rb") as f:
        mkbtfmt = f.read(0x120)
    if len(mkbtfmt) < 0x120:
        print("unable to open/read %s" % inp)
        return 2

    head_str = mkbtfmt.split(b"\x00", 1)[0]

    if b"ANDROID" in head_str:
        if to_block:
            print("Error, you can't use img file to flash directly to %s! Only sin file!" % out_arg)
            return 2
        return dump_boot(inp, out_arg)

    if (header_is_sin(mkbtfmt, head_str)):
        if to_block:
            return _convert_to_block(inp, out_arg)
        return _convert_file(inp, out_arg)

    if b"\x7fELF" in head_str:
        if to_block:
            print("Error, you can't use elf file to flash directly to %s! Only sin file!" % out_arg)
            return 2
        return extract_elf(out_arg, inp)

    if mkbtfmt[:2] == b"\x1f\x8b":
        tmp = os.path.join(out_arg, "converted.file")
        with gzip.open(inp, "rb") as gz, open(tmp, "wb") as dst:
            _copy_stream(gz, dst)
        with open(tmp, "rb") as a:
            untar(a, inp, out_arg)
        os.remove(tmp)
        return 0

    if mkbtfmt[0x101:0x105] == b"usta":
        with open(inp, "rb") as a:
            untar(a, inp, out_arg)
        return 0

    print("%s is usuported format!" % inp)
    return 2


def header_is_sin(mkbtfmt, head_str):
    """Check whether the header is in the SIN format.

    Args:
        mkbtfmt: The bytes of the header.
        head_str: The header up to the first NUL as text.

    Returns:
        bool: True when it is a SIN."""
    if b"SIN" in head_str:
        return True
    if mkbtfmt[:4] == _SIN_MAGIC2 or mkbtfmt[:4] == _SIN_MAGIC1:
        return True
    if mkbtfmt[0:1] in (b"\x01", b"\x02"):
        return True
    return False


def _convert_file(inp, out_arg):
    """Convert a SIN and write it out under a name that fits its type.

    Args:
        inp: The path of the SIN.
        out_arg: The output directory.

    Returns:
        int: 0 on success, 1 on failure."""
    fld = os.path.join(out_arg, "converted.file")
    rc = convert_sin_to_elf(inp, fld)
    if rc < 0:
        print("Error converting!")
        _safe_remove(fld)
        return 1
    if rc == 2:
        fldren = os.path.join(out_arg, _basename(inp) + ".elf")
    elif rc == 3:
        fldren = os.path.join(out_arg, _basename(inp) + ".ext4")
    else:
        fldren = os.path.join(out_arg, _basename(inp) + ".unknown")
    _safe_remove(fldren)
    try:
        os.rename(fld, fldren)
    except OSError:
        print("Error renaming \"%s\" to \"%s\"!" % (fld, fldren))
        _safe_remove(fld)
        return 1
    print("Renaming to %s succeed." % fldren)
    return 0


def _convert_to_block(inp, block):
    """Convert a SIN and write it to a block device.

    Args:
        inp: The path of the SIN.
        block: The path of the target block device.

    Returns:
        int: 0 on success, 1 on failure."""
    tmp = block + ".tmp"
    rc = convert_sin_to_elf(inp, tmp)
    if rc < 0:
        _safe_remove(tmp)
        return 1
    try:
        with open(tmp, "rb") as src, open(block, "wb") as dst:
            _copy_stream(src, dst)
    finally:
        _safe_remove(tmp)
    return 0


def _copy_stream(src, dst):
    """Copy everything from the source stream to the target stream.

    Args:
        src: The source stream.
        dst: The target stream."""
    while True:
        data = src.read(4 * 1024 * 1024)
        if not data:
            break
        dst.write(data)


def _safe_remove(path):
    """Delete a file, ignoring the errors.

    Args:
        path: The path of the file."""
    try:
        os.remove(path)
    except OSError:
        pass


def main(argv=None):
    """The command line entry point.

    Args:
        argv: The argument list, sys.argv by default.

    Returns:
        int: The exit code."""
    argv = list(sys.argv if argv is None else argv)
    if len(argv) != 3:
        print("Syntax: %s OUTPUT_FOLDER PATH_TO_FILE" % argv[0])
        return 1
    return run(argv[1], argv[2])


if __name__ == "__main__":
    sys.exit(main())
