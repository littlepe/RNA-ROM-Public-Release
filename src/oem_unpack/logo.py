#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect, export and write back the boot logo and splash images of a vendor.

The Xiaomi logo, splash and imagefv, the Motorola logo, the OPPO splash and the
Samsung logo are supported: the format is detected, the image slots are cut
out, exported as BMP, JPEG or PNG and packed back with the slot table."""

from __future__ import print_function

import gzip
import io
import os
import struct
import zlib

try:
    import lzma
except Exception:
    lzma = None

try:
    from .log import debug, debug_exc
except Exception:
    def debug(msg):
        "A placeholder for the debug output."
        pass

    def debug_exc(prefix=""):
        "A placeholder for the exception output."
        pass

LOGO_MAGIC = b"LOGO!!!!"
LOGO_MAGIC9 = b"LOGO!!!!!"
SPLASH_MAGIC = b"SPLASH!!"
OPPO_MAGIC = b"SPLASH LOGO!"
OPPO_HPPD = 0x48504444
MOTO_MAGIC = b"MotoLogo\x00"
FVH_SIG = 0x4856465F
SPLASH_HDR = 0x58881688
GUID_LZMA = bytes([
    0x98, 0x58, 0x4E, 0xEE, 0x14, 0x39, 0x59, 0x42,
    0x9D, 0x6E, 0xDC, 0x7B, 0xD7, 0x94, 0x03, 0xCF,
])
GUID_LZMAF86 = bytes([
    0xBD, 0xE6, 0x2A, 0xD4, 0x52, 0x13, 0xFB, 0x4B,
    0x90, 0x9A, 0xCA, 0x72, 0xA6, 0xEA, 0xE8, 0x89,
])
GUID_TIANO = bytes([
    0xAD, 0x80, 0x12, 0xA3, 0x1E, 0x48, 0xB6, 0x41,
    0x95, 0xE8, 0x12, 0x7F, 0x4C, 0x98, 0x47, 0x79,
])
MAX_DECOMP = 64 * 1024 * 1024
SAMSUNG_SLOTS = (
    ("slot0_small", 0x4D000, 0x8EC),
    ("slot1_main", 0x7F800, 0x9E95),
)

SCHEME_XIAOMI_LOGO = "xiaomi-logo"
SCHEME_XIAOMI_SPLASH = "xiaomi-splash"
SCHEME_XIAOMI_IMAGEFV = "xiaomi-imagefv"
SCHEME_MOTOROLA_LOGO = "motorola-logo"
SCHEME_OPPO_SPLASH = "oppo-splash"
SCHEME_SAMSUNG_LOGO = "samsung-logo"

SCHEMES = (
    SCHEME_XIAOMI_LOGO,
    SCHEME_XIAOMI_SPLASH,
    SCHEME_XIAOMI_IMAGEFV,
    SCHEME_MOTOROLA_LOGO,
    SCHEME_OPPO_SPLASH,
    SCHEME_SAMSUNG_LOGO,
)

PACKABLE = {
    SCHEME_XIAOMI_LOGO,
    SCHEME_XIAOMI_SPLASH,
    SCHEME_MOTOROLA_LOGO,
    SCHEME_OPPO_SPLASH,
    SCHEME_SAMSUNG_LOGO,
}

MAX_PIC = 32 * 1024 * 1024
MAX_DIM = 8192


def normalize_scheme(text):
    """Normalise the user input into an internal scheme name.

    Args:
        text: The raw input.

    Returns:
        str: The matching scheme, an empty string when it is unknown."""
    val = str(text or "").strip().lower().replace(" ", "-").replace("_", "-")
    if val in SCHEMES:
        return val
    if "imagefv" in val:
        return SCHEME_XIAOMI_IMAGEFV
    for name in SCHEMES:
        if name in val:
            return name
    return ""


def is_logo_type(text):
    """Check whether the type is a known logo or splash type.

    Args:
        text: The type text.

    Returns:
        bool: True for a known type."""
    return bool(normalize_scheme(text))


def can_pack_scheme(text):
    """Check whether the scheme can be packed back.

    Args:
        text: The type text.

    Returns:
        bool: True when the scheme supports packing."""
    return normalize_scheme(text) in PACKABLE


def _u16(data, off):
    """Read a little endian 16 bit integer safely.

    Args:
        data: The bytes.
        off: The offset.

    Returns:
        int: The value, 0 when it is out of bounds."""
    if off + 2 > len(data):
        return 0
    return struct.unpack_from("<H", data, off)[0]


def _u32(data, off):
    """Read a little endian 32 bit integer safely.

    Args:
        data: The bytes.
        off: The offset.

    Returns:
        int: The value, 0 when it is out of bounds."""
    if off + 4 > len(data):
        return 0
    return struct.unpack_from("<I", data, off)[0]


def _u24(data, off):
    """Read a little endian 24 bit integer safely.

    Args:
        data: The bytes.
        off: The offset.

    Returns:
        int: The value, 0 when it is out of bounds."""
    if off + 3 > len(data):
        return 0
    return data[off] | (data[off + 1] << 8) | (data[off + 2] << 16)


def _read_file(path):
    """Read a whole file.

    Args:
        path: The file path.

    Returns:
        bytes: The content of the file."""
    with open(path, "rb") as fh:
        return fh.read()


def _head(path, n=65536):
    """Read the header of a file.

    Args:
        path: The file path.
        n: The number of bytes to read.

    Returns:
        bytes: The header."""
    with open(path, "rb") as fh:
        return fh.read(n)


def _at(data, off, n):
    """Copy a slice.

    Args:
        data: The bytes.
        off: The start offset.
        n: The length.

    Returns:
        bytes: The slice, an empty string when it is out of bounds."""
    if off < 0 or off + n > len(data):
        return b""
    return bytes(data[off:off + n])


def detect_scheme(path):
    """Detect the scheme and the version of a logo image.

    The order is Motorola, OPPO, the Samsung JPEG slots, the Xiaomi imagefv, the
    Xiaomi logo and the Xiaomi splash.

    Args:
        path: The image path.

    Returns:
            tuple: (scheme, version), ("", -1) when it is not recognised."""
    # Detect the logo layout of a vendor by magic and offset (Motorola, OPPO, Samsung, Xiaomi imagefv/logo/splash).
    if not path or not os.path.isfile(path):
        return "", -1
    try:
        size = os.path.getsize(path)
    except OSError:
        return "", -1
    if size < 16:
        return "", -1
    with open(path, "rb") as fh:
        head = fh.read(min(size, 0x4200))
        extra = b""
        if size > 0x4200:
            fh.seek(0x4000)
            extra = fh.read(min(0x200, max(0, size - 0x4000)))
    data = head
    if extra and len(head) < 0x4000 + len(extra):
        data = head + b"\x00" * (0x4000 - len(head)) + extra if len(head) < 0x4000 else head[:0x4000] + extra

    if _at(data, 0, 9) == MOTO_MAGIC:
        return SCHEME_MOTOROLA_LOGO, 0
    if len(data) >= 0x4000 + len(OPPO_MAGIC) and _at(data, 0x4000, len(OPPO_MAGIC)) == OPPO_MAGIC:
        return SCHEME_OPPO_SPLASH, 0
    if _samsung_hit(path, size):
        return SCHEME_SAMSUNG_LOGO, 0x66
    fv = _find_fvh(path, size)
    if fv >= 0:
        return SCHEME_XIAOMI_IMAGEFV, 0
    ver = _xiaomi_logo_version(data, size)
    if ver >= 0:
        return SCHEME_XIAOMI_LOGO, ver
    sver = _xiaomi_splash_version(data, size)
    if sver >= 0:
        return SCHEME_XIAOMI_SPLASH, sver
    return "", -1


def _samsung_hit(path, size):
    """Check whether the fixed Samsung offsets hold JPEG data.

    Args:
        path: The image path.
        size: The size of the file.

    Returns:
        bool: True when every slot holds a JPEG."""
    need = 0
    for _name, off, ln in SAMSUNG_SLOTS:
        need = max(need, off + 3)
    if size < need:
        return False
    try:
        with open(path, "rb") as fh:
            for _name, off, ln in SAMSUNG_SLOTS:
                if off + ln > size:
                    return False
                fh.seek(off)
                mag = fh.read(3)
                if mag != b"\xff\xd8\xff":
                    return False
        return True
    except OSError:
        return False


def _find_fvh(path, size):
    """Scan for the Firmware Volume Header signature.

    Args:
        path: The image path.
        size: The size of the file.

    Returns:
        int: The offset that matched, -1 when there is none."""
    limit = min(size, 0x80000)
    try:
        with open(path, "rb") as fh:
            pos = 0
            while pos + 0x2C <= limit:
                fh.seek(pos + 0x28)
                blob = fh.read(4)
                if len(blob) == 4 and struct.unpack("<I", blob)[0] == FVH_SIG:
                    return pos
                pos += 0x1000
    except OSError:
        return -1
    return -1


def _xiaomi_logo_version(data, size):
    """Recognise the version of the Xiaomi LOGO!!!! layout.

    Args:
        data: The header of the image.
        size: The size of the file.

    Returns:
        int: The version (1-5), -1 when it is not recognised."""
    if _at(data, 0, 8) == LOGO_MAGIC:
        off16, sz20, end24 = _u32(data, 0x10), _u32(data, 0x14), _u32(data, 0x18)
        if off16 == 0 and sz20 > 100000 and size < sz20 and (end24 == 0 or sz20 <= end24):
            return 4
        return 3
    if len(data) >= 0x4009 and _at(data, 0x4000, 8) == LOGO_MAGIC:
        if len(data) > 0x4008 and data[0x4008:0x4009] == b"!":
            return 2
        e0 = (_u32(data, 0x4008) << 12) & 0xFFFFFFFF
        if e0 == 0x5000:
            return 5
        return 1
    return -1


def _xiaomi_splash_version(data, size):
    """Recognise the version of the Xiaomi SPLASH layout.

    Args:
        data: The header of the image.
        size: The size of the file.

    Returns:
        int: The version (1-7), -1 when it is not recognised."""
    if size >= 16 and _u32(data, 0) == SPLASH_HDR and _at(data, 8, 4) == b"LOGO":
        return 7
    if _at(data, 0, 8) == SPLASH_MAGIC:
        w8 = _u32(data, 8)
        h12 = _u32(data, 12)
        flag14 = _u32(data, 0x14) if len(data) >= 0x18 else 0
        if 100 <= w8 < 5001 and 100 <= h12 < 5001 and flag14 == 0:
            return 3
        if w8 == 0 and h12 == 0 and flag14 == 0:
            return 5
        if 1 <= w8 < 16:
            return 4
    if size >= 0x1008 and _at(data, 0x1000, 8) == SPLASH_MAGIC:
        return 2
    if size >= 0x4002:
        bm = _at(data, 0x4000, 2)
        if bm == b"BM":
            return 1
    return -1


def detect_path(path):
    """Detect the scheme of an image.

    Args:
        path: The image path.

    Returns:
        str: The scheme name, an empty string when it is not recognised."""
    scheme, ver = detect_scheme(path)
    return scheme


def _bmp_size(data, off):
    """Compute the size of a BMP.

    The size that is declared is used, otherwise it is estimated from the width
    and the height.

    Args:
        data: The bytes.
        off: The offset of the BMP.

    Returns:
        int: The size of the BMP, 0 when it is malformed."""
    if off + 26 > len(data) or data[off:off + 2] != b"BM":
        return 0
    size = _u32(data, off + 2)
    hdr = _u32(data, off + 14)
    w = struct.unpack_from("<i", data, off + 18)[0] if off + 22 <= len(data) else 0
    h = struct.unpack_from("<i", data, off + 22)[0] if off + 26 <= len(data) else 0
    w, h = abs(w), abs(h)
    if hdr not in (12, 40, 56, 108, 124):
        if size < 54:
            return 0
    if w > MAX_DIM or h > MAX_DIM or w < 1 or h < 1:
        return 0
    if size < 54 or size > MAX_PIC:
        row = ((w * 3 + 3) // 4) * 4
        guess = 54 + row * h
        if 54 <= guess <= MAX_PIC and off + guess <= len(data):
            return guess
        return 0
    if off + size > len(data):
        size = len(data) - off
    return size


def _jpeg_span(data, off, limit):
    """Compute the length of a JPEG.

        It starts at the SOI and ends at the EOI.

        Args:
            data: The bytes.
            off: The offset of the JPEG.
            limit: The maximum length.

        Returns:
            int: The length in bytes, 0 when it is malformed."""
    if off + 3 > len(data) or data[off:off + 2] != b"\xff\xd8":
        return 0
    end = data.find(b"\xff\xd9", off + 2, min(len(data), off + limit if limit else len(data)))
    if end < 0:
        return min(limit, len(data) - off) if limit else 0
    return end + 2 - off


def _png_span(data, off):
    """Compute the length of a PNG.

        The scan ends at the IEND chunk.

        Args:
            data: The bytes.
            off: The offset of the PNG.

        Returns:
            int: The length in bytes, 0 when it is malformed."""
    if _at(data, off, 8) != b"\x89PNG\r\n\x1a\n":
        return 0
    pos = off + 8
    while pos + 12 <= len(data):
        ln = _u32(data, pos)
        ctype = _at(data, pos + 4, 4)
        pos += 12 + ln
        if ctype == b"IEND":
            return pos - off
        if ln > MAX_PIC:
            break
    return 0


def _pic_kind(blob):
    """Tell the type of an image from its magic bytes.

    Args:
        blob: The block of data.

    Returns:
        str: One of bmp, jpg, png, gz or bin."""
    if blob.startswith(b"BM"):
        return "bmp"
    if blob.startswith(b"\xff\xd8"):
        return "jpg"
    if blob.startswith(b"\x89PNG"):
        return "png"
    if blob.startswith(b"\x1f\x8b"):
        return "gz"
    return "bin"


def _scan_bmps(data, start=0, end=None, max_n=64):
    """Scan a range for the BMP slots.

    Args:
        data: The bytes.
        start: The start offset.
        end: The end offset, to the end of the data by default.
        max_n: The maximum number of slots.

    Returns:
        list: The (offset, size, "bmp") triples."""
    end = len(data) if end is None else min(end, len(data))
    slots = []
    pos = start
    while pos + 54 <= end and len(slots) < max_n:
        idx = data.find(b"BM", pos, end)
        if idx < 0:
            break
        size = _bmp_size(data, idx)
        if size:
            slots.append((idx, size, "bmp"))
            pos = idx + size
        else:
            pos = idx + 2
    return slots


def _table_pairs(data, start, stop, shift=0, max_n=64):
    """Read the offset and size table.

    Args:
        data: The bytes.
        start: The offset of the table.
        stop: The offset where the table ends.
        shift: The number of bits the values are shifted by.
        max_n: The maximum number of entries.

    Returns:
        list: The (offset, size, type) triples."""
    slots = []
    pos = start
    stop = min(stop, len(data))
    while pos + 8 <= stop and len(slots) < max_n:
        off = _u32(data, pos)
        sz = _u32(data, pos + 4)
        if shift:
            off = (off << shift) & 0xFFFFFFFF
            sz = (sz << shift) & 0xFFFFFFFF
        pos += 8
        if off == 0 or sz == 0:
            break
        if sz > MAX_PIC or off >= len(data):
            break
        if off + sz > len(data):
            sz = len(data) - off
        if sz <= 0:
            break
        slots.append((off, sz, _pic_kind(_at(data, off, 8))))
    return slots


def _xiaomi_logo_slots(data):
    """Parse the slots of a Xiaomi logo.

        The offset table is tried first, then the scan and the carving of a BMP.

        Args:
            data: The image data.

        Returns:
            list: The (offset, size, type) triples."""
    if _at(data, 0x4000, 8) == LOGO_MAGIC:
        for shift in (12, 0):
            stop = 0x4200 if _at(data, 0x4000, 9) == LOGO_MAGIC9 else 0x5000
            slots = _table_pairs(data, 0x4008, stop, shift=shift)
            if slots:
                return slots
    if _at(data, 0, 8) == LOGO_MAGIC:
        for shift in (0, 12):
            slots = _table_pairs(data, 8, min(0x1000, len(data)), shift=shift)
            if slots:
                return slots
    found = _scan_bmps(data, 0)
    if found:
        return found


    carved = _carve_images(data, max_n=256)
    return [(o, s, k) for o, s, k, _n in carved]


def _splash_rgb_slots(data):
    """Parse the RGB888 frames of a SPLASH!!.

    Args:
        data: The image data.

    Returns:
        list: The (offset, size, "rgb888", width, height) tuples."""
    slots = []
    pos = 0
    while pos + 0x200 <= len(data) and len(slots) < 32:
        if _at(data, pos, 8) != SPLASH_MAGIC:
            if pos == 0:
                break
            pos += 0x200
            continue
        w = _u32(data, pos + 8)
        h = _u32(data, pos + 12)
        flag = _u32(data, pos + 0x14) if pos + 0x18 <= len(data) else 0
        if 100 <= w < 5001 and 100 <= h < 5001 and flag == 0:
            payload = w * h * 3
            total = 0x200 + payload
            if pos + total > len(data):
                break
            slots.append((pos, total, "rgb888", w, h))
            pos += total
            continue
        pos += 0x200
    return slots


def _splash_slots(data):
    """Parse the slots of a Xiaomi splash.

        The RGB frames are tried first, then the scan of a BMP.

        Args:
            data: The image data.

        Returns:
            list: The slots."""
    rgb = _splash_rgb_slots(data)
    if rgb:
        return rgb
    if _at(data, 0x1000, 8) == SPLASH_MAGIC:
        found = _scan_bmps(data, 0x1000)
        if found:
            return [(o, s, k) for o, s, k in found]
    if _u32(data, 0) == SPLASH_HDR:
        found = _scan_bmps(data, 0x200)
        if found:
            return [(o, s, k) for o, s, k in found]
    found = _scan_bmps(data, 0x4000 if len(data) > 0x4000 else 0)
    return [(o, s, k) for o, s, k in found]


def _moto_slots(data):
    """Parse the slots that follow the Motorola MotoLogo.

    Args:
        data: The image data.

    Returns:
        list: The slots."""
    found = _scan_bmps(data, 16)
    if found:
        return found

    for off in range(16, min(64, len(data))):
        if _at(data, off, 2) == b"BM":
            sz = _bmp_size(data, off)
            if sz:
                return [(off, sz, "bmp")]
    return [(16, len(data) - 16, "bin")] if len(data) > 16 else []


def _oppo_slots(data):




    """Parse the directory table of the OPPO SPLASH LOGO!.

        The entries sit at 0x4120 and the base of the data is 0x8000.

        Args:
            data: The image data.

        Returns:
            list: The (offset, size, type, name) tuples."""
    if _at(data, 0x4000, len(OPPO_MAGIC)) != OPPO_MAGIC:
        return []
    count = _u32(data, 0x410C)
    if not (1 <= count < 0x81):
        return _scan_bmps(data, 0x4120)
    slots = []
    pos = 0x4120
    for _i in range(count):
        if pos + 0xC > len(data):
            break
        off = 0x8000 + _u32(data, pos)
        size = _u32(data, pos + 8)
        name = _ui_name(_at(data, pos + 0xC, 0x80 - 0xC))
        pos += 0x80
        if off <= 0 or size == 0 or size > MAX_PIC or off >= len(data):
            continue
        if off + size > len(data):
            size = len(data) - off
        slots.append((off, size, _pic_kind(_at(data, off, 8)), name))
    return slots or _scan_bmps(data, 0x4120)


def _samsung_slots(data):
    """Cut the Samsung JPEG out of its fixed slots.

    Args:
        data: The image data.

    Returns:
        list: The (offset, size, "jpg", name) tuples."""
    slots = []
    for name, off, ln in SAMSUNG_SLOTS:
        if off + ln <= len(data) and _at(data, off, 3) == b"\xff\xd8\xff":
            span = _jpeg_span(data, off, ln) or ln
            slots.append((off, min(span, ln), "jpg", name))
    return slots


def _align4(n):
    """Round up to a multiple of 4 bytes.

    Args:
        n: The raw value.

    Returns:
        int: The aligned value."""
    return (n + 3) & ~3


def _align8(n):
    """Round up to a multiple of 8 bytes.

    Args:
        n: The raw value.

    Returns:
        int: The aligned value."""
    return (n + 7) & ~7


def _lzma_props_ok(blob):
    """Check whether the LZMA properties byte is valid.

    Args:
        blob: At least one byte of data.

    Returns:
        bool: True when it is valid."""
    if not blob:
        return False
    return (blob[0] // 9 // 5) <= 4


def _efi_lzma(blob):
    """Try to decompress an EFI or a plain LZMA blob.

    Args:
        blob: The compressed data.

    Returns:
        bytes: The decompressed data, an empty string on failure."""
    if not blob or lzma is None:
        return b""
    cands = [blob]
    if len(blob) > 5 and (not _lzma_props_ok(blob[:1])) and _lzma_props_ok(blob[4:5]):
        cands.insert(0, blob[4:])
    for cand in cands:
        if not cand:
            continue
        for fmt_name in ("FORMAT_ALONE", "FORMAT_AUTO"):
            fmt = getattr(lzma, fmt_name, None)
            if fmt is None:
                continue
            try:
                out = lzma.decompress(cand, format=fmt)
            except Exception:
                continue
            if out and len(out) <= MAX_DECOMP:
                return out
    return b""


def _ffs_file_at(data, pos, end):
    """Parse the header of a Firmware File System file.

    Args:
        data: The bytes.
        pos: The offset of the file.
        end: The offset where the readable data ends.

    Returns:
        tuple: (type, length, header size), None when it is malformed."""
    if pos + 0x18 > end:
        return None
    if data[pos:pos + 0x18] == b"\xff" * 0x18:
        return None
    ftype = data[pos + 0x12]
    attr = data[pos + 0x13]
    flen = _u24(data, pos + 0x14)
    hdr = 0x18
    if flen == 0xFFFFFF or (attr & 0x01):
        if pos + 0x20 > end:
            return None
        ext = struct.unpack_from("<Q", data, pos + 0x18)[0]
        if ext >= 0x20:
            flen = int(ext)
            hdr = 0x20
    if flen < hdr or pos + flen > end:
        return None
    return ftype, flen, hdr


def _iter_ffs(data, fv_off, end):
    """Walk the FFS files of a firmware volume.

    Args:
        data: The bytes.
        fv_off: The offset of the volume.
        end: The offset where it ends.

    Yields:
        tuple: (offset, length, type, header size)."""
    if fv_off + 0x30 > end or _u32(data, fv_off + 0x28) != FVH_SIG:
        return
    hdr_len = _u16(data, fv_off + 0x30)
    fv_len = struct.unpack_from("<Q", data, fv_off + 0x20)[0]
    if hdr_len < 0x38 or fv_len < hdr_len:
        fv_len = min(end - fv_off, 0x8000000)
    limit = min(end, fv_off + int(fv_len))
    pos = fv_off + hdr_len
    while pos + 0x18 <= limit:
        info = _ffs_file_at(data, pos, limit)
        if info is None:
            break
        ftype, flen, hdr = info
        if ftype not in (0xF0, 0xFF, 0x00):
            yield pos, flen, ftype, hdr
        nxt = _align8(pos + flen)
        if nxt <= pos:
            break
        pos = nxt


def _iter_sections(data, start, end):
    """Walk the sections of an FFS file.

    Args:
        data: The bytes.
        start: The start offset.
        end: The end offset.

    Yields:
        tuple: (type, data offset, data length)."""
    pos = start
    while pos + 4 <= end:
        slen = _u24(data, pos)
        stype = data[pos + 3]
        hdr = 4
        if slen == 0xFFFFFF:
            if pos + 8 > end:
                break
            slen = _u32(data, pos + 4)
            hdr = 8
        if slen < hdr or pos + slen > end:
            break
        yield stype, pos + hdr, slen - hdr
        nxt = _align4(pos + slen)
        if nxt <= pos:
            break
        pos = nxt


def _fv_files(data, fv_off):
    """List the files of a firmware volume.

    Args:
        data: The bytes.
        fv_off: The offset of the volume.

    Returns:
        list: The (offset, length, type) triples."""
    files = []
    for pos, flen, ftype, _hdr in _iter_ffs(data, fv_off, len(data)):
        files.append((pos, flen, ftype))
    return files


def _fv_sections(data, file_off, file_len):
    """List the sections of one FFS file.

    Args:
        data: The bytes.
        file_off: The offset of the file.
        file_len: The length of the file.

    Returns:
        list: The (type, data offset, data length) triples."""
    end = min(len(data), file_off + file_len)
    info = _ffs_file_at(data, file_off, end) if file_off + 0x18 <= end else None
    hdr = info[2] if info else 0x18
    out = []
    for stype, soff, slen in _iter_sections(data, file_off + hdr, end):
        out.append((stype, soff, slen))
    return out


def _ui_name(blob):
    """Pick the UI name out of ASCII or UTF-16LE data.

    Args:
        blob: The raw bytes.

    Returns:
        str: The name, an empty string when it is not valid."""
    if not blob:
        return ""



    def _is_utf16(buf):
        """Guess whether the bytes are ASCII in UTF-16LE.

        Args:
            buf: The bytes.

        Returns:
            bool: True for ASCII that looks like UTF-16LE."""
        n = 0
        for i in range(0, len(buf) - 1, 2):
            lo, hi = buf[i], buf[i + 1]
            if hi != 0:
                return False
            if lo == 0:
                break
            if not (32 <= lo < 127):
                return False
            n += 1
            if n >= 4:
                break
        return n >= 2
    if _is_utf16(blob):
        try:


            text = blob.decode("utf-16le", "ignore").split("\x00")[0].strip()
            if text:
                return text
        except Exception:
            pass
    try:
        text = blob.split(b"\x00")[0].decode("ascii", "ignore").strip().strip("\x00")
    except Exception:
        text = ""
    return text


def _looks_like_image(blob):
    """Check whether the header looks like an image.

    Args:
        blob: The block of data.

    Returns:
        bool: True for something that looks like a BMP, gzip, PNG or JPEG."""
    return blob[:2] == b"BM" or blob[:2] == b"\x1f\x8b" or blob[:4] == b"\x89PNG" or blob[:3] == b"\xff\xd8\xff"


def _carve_try(data, table_abs, blob_base, shift):
    """Cut the images out of blob_base with the offset and size table.

    Args:
        data: The bytes.
        table_abs: The absolute offset of the table.
        blob_base: The base of the data.
        shift: The number of bits the values are shifted by.

    Returns:
        list: The (offset, size, type, "") tuples, empty when the first entry is not
            an image."""
    slots = []
    pos = table_abs
    n = 0
    while pos + 8 <= len(data) and n < 64:
        off = _u32(data, pos)
        sz = _u32(data, pos + 4)
        pos += 8
        if shift:
            off = (off << shift) & 0xFFFFFFFF
            sz = (sz << shift) & 0xFFFFFFFF
        if off == 0 or sz == 0 or sz > MAX_PIC:
            break
        aoff = blob_base + off
        if aoff < 0 or aoff >= len(data):
            break
        if aoff + sz > len(data):
            sz = len(data) - aoff
        if sz <= 0:
            break
        head = _at(data, aoff, 8)
        if n == 0 and not _looks_like_image(head):
            return []
        slots.append((aoff, sz, _pic_kind(head), ""))
        n += 1
    return slots if n >= 1 else []


def _carve_logo_slots(data):





    """Look for LOGO!!!! and try to carve the offset table.

    Args:
        data: The image data.

    Returns:
        list: The slots."""
    start = 0
    while True:
        base = data.find(LOGO_MAGIC, start)
        if base < 0:
            break

        slots = _carve_try(data, base + 8, base, 0)
        if not slots and base >= 0x4000:

            slots = _carve_try(data, base + 8, base - 0x4000, 12)
        if slots:
            return slots
        start = base + 8
    return []


def _carve_images(data, max_n=256):
    """Scan the whole image for gzipped BMP, PNG and JPEG data.

    Args:
        data: The image data.
        max_n: The maximum number of slots.

    Returns:
        list: The (offset, size, type, "") tuples."""
    import zlib

    slots = []
    n = 0
    pos = 0
    end = len(data)
    mv = memoryview(data)
    while n < max_n:
        idx = -1
        for sig in (b"\x1f\x8b", b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff"):
            j = data.find(sig, pos)
            if j >= 0 and (idx < 0 or j < idx):
                idx = j
                hit = sig
        if idx < 0:
            break
        span = 0
        kind = ""
        if hit == b"\x1f\x8b":


            win = mv[idx: idx + min(MAX_PIC, end - idx)]
            try:
                d = zlib.decompressobj(16 + zlib.MAX_WBITS)
                dec = d.decompress(win, MAX_PIC)
                if d.eof and dec[:2] == b"BM":
                    span = len(win) - len(d.unused_data)
                    kind = "gz"
            except Exception:
                span = 0
        elif hit == b"\x89PNG\r\n\x1a\n":
            span = _png_span(data, idx)
            kind = "png" if span else ""
        else:
            span = _jpeg_span(data, idx, MAX_PIC)
            kind = "jpg" if span else ""
        if span and idx + span <= end:
            slots.append((idx, span, kind, ""))
            n += 1
            pos = idx + span
        else:
            pos = idx + 2
    return slots


def _guid_defined_decode(chunk):
    """Decode an EFI GUID_DEFINED section.

    Args:
        chunk: The data of the section.

    Returns:
        bytes: The decoded data, the original content when it cannot be
            decompressed."""
    if len(chunk) < 20:
        return b""
    guid = bytes(chunk[:16])
    doff = _u16(chunk, 16)
    rel = doff - 4
    if rel < 20 or rel >= len(chunk):
        rel = 20
    body = chunk[rel:]
    if guid in (GUID_LZMA, GUID_LZMAF86, GUID_TIANO) or _lzma_props_ok(body[:1]):
        dec = _efi_lzma(body)
        if dec:
            return dec
    return body


def _add_payload_slots(slots, payload, name, off=0):
    """Add a PE32 or raw section to the slots, as logo.img or as an image.

    Args:
        slots: The slots to add to.
        payload: The data of the section.
        name: The name of the section.
        off: The offset of the base of the data."""
    if not payload:
        return
    low = (name or "").lower()
    logo_like = (
        low.endswith("logo.img")
        or payload.startswith(LOGO_MAGIC)
        or (len(payload) > 0x4008 and payload[0x4000:0x4008] == LOGO_MAGIC)
    )
    if logo_like:
        found = _xiaomi_logo_slots(payload)
        if found:
            for item in found:
                o, s, k = item[0], item[1], item[2]
                blob = payload[o:o + s]
                if blob:
                    slots.append((o, s, k, "logo_{:03d}".format(len(slots)), blob))
            return
        carved = _carve_images(payload, max_n=256)
        if carved:
            for o, s, k, _n in carved:
                blob = payload[o:o + s]
                if blob:
                    slots.append((o, s, k, "logo_{:03d}".format(len(slots)), blob))
            return
        blob = payload
        use = off
        if len(payload) > 0x4008 and payload[0x4000:0x4008] == LOGO_MAGIC:
            blob = payload[0x4000:]
            use = 0x4000
        slots.append((use, len(blob), "bin", name or "logo.img", blob))
        return
    if _looks_like_image(payload) or low.endswith((".bmp", ".bmp.gz", ".png", ".jpg", ".jpeg")):
        slots.append((off, len(payload), _pic_kind(payload), name or "fv.bin", payload))


def _walk_sections(data, start, end, slots, depth):
    """Walk the EFI section tree and collect the images.

    Args:
        data: The bytes.
        start: The start offset.
        end: The end offset.
        slots: The slots to add to.
        depth: The current depth of the recursion."""
    if depth > 8 or start >= end:
        return
    name = ""
    payload = b""
    poff = 0
    for stype, soff, slen in _iter_sections(data, start, end):
        chunk = bytes(data[soff:soff + slen])
        if stype == 0x15:
            name = _ui_name(chunk)
        elif stype == 0x19:
            payload = chunk
            poff = soff
        elif stype == 0x01 and len(chunk) >= 5:
            body = chunk[5:]
            dec = body if chunk[4] == 0 else _efi_lzma(body)
            if dec:
                debug("imagefv compress type={} -> {}B".format(chunk[4], len(dec)))
                _walk_sections(dec, 0, len(dec), slots, depth + 1)
                _walk_fv_blob(dec, slots, depth + 1)
        elif stype == 0x02:
            dec = _guid_defined_decode(chunk)
            if dec:
                debug("imagefv guid-defined -> {}B".format(len(dec)))
                _walk_sections(dec, 0, len(dec), slots, depth + 1)
                _walk_fv_blob(dec, slots, depth + 1)
        elif stype == 0x17:
            _walk_fv_blob(chunk, slots, depth + 1)
    if payload:
        _add_payload_slots(slots, payload, name, poff)


def _walk_fv_blob(blob, slots, depth):
    """Find the firmware volumes in a blob and walk the FFS files.

    Args:
        blob: The block of data.
        slots: The slots to add to.
        depth: The current depth of the recursion."""
    if depth > 8 or len(blob) < 0x38:
        return
    fv = -1
    if _u32(blob, 0x28) == FVH_SIG:
        fv = 0
    else:
        pos = 0
        limit = min(len(blob), 0x80000)
        while pos + 0x2C <= limit:
            if _u32(blob, pos + 0x28) == FVH_SIG:
                fv = pos
                break
            pos += 0x1000
    if fv < 0:
        return
    for pos, flen, _ftype, hdr in _iter_ffs(blob, fv, len(blob)):
        _walk_sections(blob, pos + hdr, pos + flen, slots, depth + 1)


def _imagefv_slots(data):
    """Parse the slots of a Xiaomi imagefv.

        The firmware volumes are walked first, the data is carved when that fails.

    Args:
        data: The image data.

    Returns:
        list: The slots."""
    slots = []
    try:
        _walk_fv_blob(data, slots, 0)
    except Exception:
        debug_exc("imagefv FV walk: ")
        slots = []
    if not slots:
        slots = _carve_logo_slots(data)
    if not slots:
        for off, sz, kind in _scan_bmps(data, 0, max_n=32):
            slots.append((off, sz, kind, "bmp"))
    if not slots:
        slots = _carve_images(data)
    return slots


def find_slots(data, scheme):
    """Return the slots of a scheme.

    Args:
        data: The image data.
        scheme: The name of the scheme.

    Returns:
        list: The slot tuples."""
    # Cut the slots per scheme: an offset table, RGB frames, the OPPO directory, a fixed Samsung slot or a walk over the FV.
    if scheme == SCHEME_XIAOMI_LOGO:
        return [(o, s, k, "") for o, s, k in _xiaomi_logo_slots(data)]
    if scheme == SCHEME_XIAOMI_SPLASH:
        norm = []
        for item in _splash_slots(data):
            if len(item) == 5:
                norm.append(item)
            else:
                o, s, k = item
                norm.append((o, s, k, 0, 0))
        return norm
    if scheme == SCHEME_XIAOMI_IMAGEFV:
        return _imagefv_slots(data)
    if scheme == SCHEME_MOTOROLA_LOGO:
        return [(o, s, k, "") for o, s, k in _moto_slots(data)]
    if scheme == SCHEME_OPPO_SPLASH:
        return _oppo_slots(data)
    if scheme == SCHEME_SAMSUNG_LOGO:
        return _samsung_slots(data)
    return []


def rgb888_to_bmp(rgb, width, height):
    """Turn top down RGB888 into a 24 bit BMP.

    Args:
        rgb: The RGB888 data.
        width: The width.
        height: The height.

    Returns:
        bytes: The BMP."""
    row = ((width * 3 + 3) // 4) * 4
    raw = bytearray(row * height)
    src_row = width * 3
    for y in range(height):
        src = (height - 1 - y) * src_row
        dst = y * row
        for x in range(width):
            r = rgb[src + x * 3]
            g = rgb[src + x * 3 + 1]
            b = rgb[src + x * 3 + 2]
            raw[dst + x * 3] = b
            raw[dst + x * 3 + 1] = g
            raw[dst + x * 3 + 2] = r
    dib = struct.pack("<IiiHHIIiiII", 40, width, height, 1, 24, 0, len(raw), 2835, 2835, 0, 0)
    hdr = struct.pack("<2sIHHI", b"BM", 14 + 40 + len(raw), 0, 0, 54)
    return bytes(hdr + dib + raw)


def bmp_to_rgb888(blob):
    """Turn a 24 bit uncompressed BMP into top down RGB888.

    Args:
        blob: The BMP.

    Returns:
        tuple: (RGB data, width, height).

    Raises:
        ValueError: When it is not a BMP, the header is not supported or the data
            is incomplete."""
    if len(blob) < 54 or blob[:2] != b"BM":
        raise ValueError("This is not a BMP")
    offbits = _u32(blob, 10)
    hdr = _u32(blob, 14)
    if hdr < 40:
        raise ValueError("Unsupported BMP header")
    w = struct.unpack_from("<i", blob, 18)[0]
    h = struct.unpack_from("<i", blob, 22)[0]
    bits = _u16(blob, 28)
    comp = _u32(blob, 30)
    if bits != 24 or comp != 0:
        raise ValueError("Please use a 24 bit uncompressed BMP")
    bottom_up = h > 0
    h = abs(h)
    w = abs(w)
    row = ((w * 3 + 3) // 4) * 4
    need = offbits + row * h
    if need > len(blob):
        raise ValueError("The BMP data is incomplete")
    out = bytearray(w * h * 3)
    for y in range(h):
        src_y = y if not bottom_up else (h - 1 - y)
        src = offbits + src_y * row
        dst = y * w * 3
        for x in range(w):
            b = blob[src + x * 3]
            g = blob[src + x * 3 + 1]
            r = blob[src + x * 3 + 2]
            out[dst + x * 3] = r
            out[dst + x * 3 + 1] = g
            out[dst + x * 3 + 2] = b
    return bytes(out), w, h


def _ext_for(kind, name=""):
    """Pick the extension of the export.

    Args:
        kind: The type of the image.
        name: The original file name.

    Returns:
        str: The extension."""
    low = (name or "").lower()
    if low.endswith(".bmp.gz"):
        return ".bmp.gz"
    if kind == "jpg":
        return ".jpg"
    if kind == "png":
        return ".png"
    if kind == "gz":
        return ".bmp.gz"
    if kind == "rgb888":
        return ".bmp"
    if kind == "bin":
        if "logo" in low or low.endswith(".img"):
            return ".img"
        return ".bin"
    return ".bmp"


def write_slots_file(path, slots):
    """Write the text of the slot table.

    Args:
        path: The path of the output file.
        slots: The slot dictionaries."""
    lines = ["# idx offset size file encoding width height"]
    for i, slot in enumerate(slots):
        lines.append("{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6}".format(
            i, slot["offset"], slot["size"], slot["file"], slot["enc"],
            slot.get("width", 0), slot.get("height", 0)))
    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")


def read_slots_file(path):
    """Read the slot table back.

    Args:
        path: The path of the slot table.

    Returns:
        list: The slot dictionaries."""
    slots = []
    with open(path, "r") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.replace(",", " ").split()
            if len(parts) < 5:
                continue
            slots.append({
                "offset": int(parts[1], 0),
                "size": int(parts[2], 0),
                "file": parts[3],
                "enc": parts[4],
                "width": int(parts[5]) if len(parts) > 5 else 0,
                "height": int(parts[6]) if len(parts) > 6 else 0,
            })
    return slots


def extract_logo(src, out_dir, raw_path, label=""):
    """Detect the scheme and export the slot images, the raw image is saved as
    a backup at the same time.

    Args:
        src: The path of the source image.
        out_dir: The directory the images go to.
        raw_path: The path of the raw backup.
        label: An extra label.

    Returns:
        dict: The result of the export, None when the scheme is not known.

    Raises:
        RuntimeError: When no image slot can be exported."""
    # Export: detect the scheme, write the raw backup and the slot images, print the magic diagnostics when imagefv fails.
    scheme, version = detect_scheme(src)
    if not scheme:
        return None
    data = _read_file(src)
    raw = find_slots(data, scheme)
    if not raw:

        if scheme == SCHEME_XIAOMI_IMAGEFV:
            from collections import defaultdict
            sigs = defaultdict(int)
            for pos in range(min(len(data), 0x200000) - 8):
                if data[pos:pos + 8] == LOGO_MAGIC:
                    sigs["LOGO!!!!"] += 1
                elif data[pos:pos + 2] == b"BM":
                    sigs["BM"] += 1
                elif data[pos:pos + 2] == b"\x1f\x8b":
                    sigs["GZ"] += 1
                elif data[pos:pos + 4] == b"\x89PNG":
                    sigs["PNG"] += 1
                elif data[pos:pos + 3] == b"\xff\xd8\xff":
                    sigs["JPEG"] += 1
                elif data[pos:pos + 4] == b"\x04\"M\x18":
                    sigs["LZ4"] += 1
                elif data[pos:pos + 4] == b"\x02!L\x18":
                    sigs["LZ4_LEGACY"] += 1
                elif data[pos:pos + 4] == b"\x28\xb5\x2f\xfd":
                    sigs["ZSTD"] += 1
                elif data[pos:pos + 4] == b"\xfd7zXZ":
                    sigs["XZ"] += 1
            fv_found = _find_fvh(src, len(data)) >= 0
            debug("imagefv diag: FV_ok={} size={} sigs={}".format(
                fv_found, len(data),
                dict((k, v) for k, v in sorted(sigs.items()) if v)))
        raise RuntimeError("No image slot to export was found in the image")
    os.makedirs(out_dir, exist_ok=True)
    raw_dir = os.path.dirname(raw_path)
    if raw_dir:
        os.makedirs(raw_dir, exist_ok=True)
    with open(raw_path, "wb") as fh:
        fh.write(data)
    slots = []
    used = {}
    for i, item in enumerate(raw):
        width = height = 0
        hint = ""
        payload_bytes = None
        if scheme == SCHEME_XIAOMI_SPLASH and len(item) == 5:
            off, size, enc, width, height = item
        elif scheme == SCHEME_XIAOMI_IMAGEFV and len(item) >= 4:
            off, size, enc = item[0], item[1], item[2]
            hint = item[3] if len(item) > 3 else ""
            if len(item) > 4 and item[4]:
                payload_bytes = bytes(item[4])
        elif scheme == SCHEME_SAMSUNG_LOGO and len(item) >= 4:
            off, size, enc = item[0], item[1], item[2]
            hint = item[3] if len(item) > 3 else ""
        else:
            off, size, enc = item[0], item[1], item[2]
            if len(item) > 3 and isinstance(item[3], str):
                hint = item[3]
            if len(item) > 4 and item[4]:
                payload_bytes = bytes(item[4])
        blob = payload_bytes if payload_bytes is not None else bytes(data[off:off + size])
        if enc == "rgb888" and width and height:
            payload = blob[0x200:]
            blob = rgb888_to_bmp(payload, width, height)
            ext = ".bmp"
        else:
            if enc == "gz" or blob.startswith(b"\x1f\x8b"):
                try:
                    blob = gzip.decompress(blob)
                    enc = "gz"
                except Exception:
                    debug_exc("gzip slot: ")

            ext = _ext_for(_pic_kind(blob), hint)
        base = "{:02d}".format(i)
        if hint:
            stem = os.path.basename(hint.replace("\\", "/"))
            for suf in (".bmp.gz", ".gz", ".bmp", ".png", ".jpg", ".jpeg", ".img", ".bin"):
                if stem.lower().endswith(suf):
                    stem = stem[: -len(suf)]
                    break
            stem = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in stem)[:40]
            if stem:
                name = stem + ext
            else:
                name = base + ext
        else:
            name = base + ext
        if name in used:
            name = base + "_" + name
        used[name] = True
        dest = os.path.join(out_dir, name)
        with open(dest, "wb") as fh:
            fh.write(blob)
        slots.append({
            "offset": off,
            "size": size,
            "file": name,
            "enc": enc,
            "width": width,
            "height": height,
        })
        debug("logo slot {} off={} size={} file={} enc={}".format(i, off, size, name, enc))
    return {
        "scheme": scheme,
        "version": version,
        "packable": 1 if can_pack_scheme(scheme) else 0,
        "size": len(data),
        "raw": raw_path,
        "slots": slots,
        "count": len(slots),
    }


def _prepare_slot_bytes(slot, blob):
    """Fit the image of the user back into the slot, with the encoding of
    the slot.

    Args:
        slot: The slot dictionary.
        blob: The image data.

    Returns:
        tuple: (the padded slot data, the payload, the offset of the payload).

    Raises:
        ValueError: When the size does not match or the image is too large."""
    enc = slot.get("enc") or "bmp"
    size = int(slot["size"])
    if enc == "rgb888":
        rgb, w, h = bmp_to_rgb888(blob)
        want_w = int(slot.get("width") or 0)
        want_h = int(slot.get("height") or 0)
        if want_w and want_h and (w != want_w or h != want_h):
            raise ValueError("The image has to be {}x{}, it is {}x{}".format(want_w, want_h, w, h))
        payload = rgb
        need = 0x200 + len(payload)
        if need > size:
            raise ValueError("The image is too large, it needs {} bytes and the slot holds {}".format(need, size))
        out = bytearray(size)
        return bytes(out), payload, 0x200
    if enc == "gz":
        packed = gzip.compress(blob)
        if len(packed) > size:
            raise ValueError("The image is too large (gzip {} > slot {})".format(len(packed), size))
        return packed, packed, 0
    if len(blob) > size:
        raise ValueError("The image is too large ({} > slot {})".format(len(blob), size))
    return blob, blob, 0


def pack_logo(src_dir, raw_path, out_img, slots_path):
    """Write the images back into the original image with the slot table.

        The total length of the image stays the same.

    Args:
        src_dir: The directory that holds the images.
        raw_path: The path of the original raw image.
        out_img: The path of the image to write.
        slots_path: The path of the slot table.

    Returns:
        int: The size of the image in bytes.

    Raises:
        RuntimeError: When a file is missing or the size of the image changed."""
    # Write back: put the images at their original offsets, the total size of the image must not change.
    if not os.path.isfile(raw_path):
        raise RuntimeError("The original image was not found: {}".format(raw_path))
    if not os.path.isfile(slots_path):
        raise RuntimeError("The slot table was not found")
    slots = read_slots_file(slots_path)
    if not slots:
        raise RuntimeError("The slot table is empty")
    data = bytearray(_read_file(raw_path))
    orig_len = len(data)
    for slot in slots:
        pic = os.path.join(src_dir, slot["file"])
        if not os.path.isfile(pic):
            alt = os.path.join(src_dir, os.path.basename(slot["file"]))
            pic = alt if os.path.isfile(alt) else pic
        if not os.path.isfile(pic):
            debug("logo skip missing {}".format(slot["file"]))
            continue
        with open(pic, "rb") as fh:
            blob = fh.read()
        try:
            packed, payload, payload_off = _prepare_slot_bytes(slot, blob)
        except ValueError:
            raise
        off = int(slot["offset"])
        size = int(slot["size"])
        if off < 0 or off + size > len(data):
            raise RuntimeError("The slot reaches past the original image: {}+{}".format(off, size))
        if slot.get("enc") == "rgb888":
            end = off + payload_off + len(payload)
            if end - off > size:
                raise ValueError("The image is too large")
            data[off + payload_off:off + payload_off + len(payload)] = payload
        else:
            data[off:off + len(packed)] = packed
            if len(packed) < size:
                fill = size - len(packed)
                if slot.get("enc") in ("bmp", "jpg", "png", "gz", "bin"):
                    data[off + len(packed):off + size] = b"\x00" * fill
    if len(data) != orig_len:
        raise RuntimeError("The size of the image changed, aborted")
    out_dir = os.path.dirname(out_img)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(out_img, "wb") as fh:
        fh.write(data)
    if os.path.getsize(out_img) != orig_len:
        raise RuntimeError("The size of the image does not match after writing")
    return orig_len
