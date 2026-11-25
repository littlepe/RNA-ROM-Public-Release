#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unpack and pack Rockchip RKFW and RKAF firmware.

The outer RKFW header (the BOOT plus the embedded update.img) and the RKAF
partition table are parsed, the 32 bit wrap of the sizes above 4GiB is undone
and the package-file can be used to pack the firmware again."""

from __future__ import print_function

import argparse
import hashlib
import os
import re
import shutil
import struct
import sys

try:
    from . import listing
except ImportError:
    import listing


def _log_tr(text):
    """The output is English, the translation is the identity."""
    return text

try:
    from concurrent.futures import ThreadPoolExecutor
except Exception:
    ThreadPoolExecutor = None


def _extract_threads():
    """Resolve the number of threads used for the extraction.

    Reads RNA_THREADS/DNA_THREADS and falls back to the CPU count.

    Returns:
        int: The thread count."""
    raw = os.getenv("RNA_THREADS") or os.getenv("DNA_THREADS") or os.getenv("WORK_THREADS") or ""
    try:
        count = int(float(raw))
    except (TypeError, ValueError):
        count = 0
    if count <= 0:
        count = max(1, os.cpu_count() or 2)
    return count


try:
    from .log import debug, debug_exc, file_info
    from .log import out as echo
except Exception:
    def debug(msg):
        """A placeholder for the debug output.

        Args:
            msg: The text."""
        pass

    def debug_exc(prefix="exception: "):
        """A placeholder for the exception output.

        Args:
            prefix: The prefix."""
        pass

    def file_info(path):
        """A placeholder for the file information.

        Args:
            path: The path.

        Returns:
            str: The path, unchanged."""
        return str(path)

    def echo(msg):
        """Write one line to the console.

        Args:
            msg: The text."""
        print(str(msg))

CHUNK = 4 * 1024 * 1024
# The container magics: the outer RKFW package, the embedded RKAF update.img and the PARM area.
RKFW_SIGNATURE = b"RKFW"
RKAF_SIGNATURE = b"RKAF"
PARM_SIGNATURE = b"PARM"
# The RKFW header is 0x66 bytes, the RKAF header is always 2048 bytes with at most 16 partitions and a sector size of 2048.
RKFW_HEADER_SIZE = 0x66
RKAF_HEADER_SIZE = 2048
MAX_PARTS = 16
SECTOR_SIZE = 2048
U32_RANGE = 1 << 32

# The chip family codes and their names, the older platforms (0x50/51/60/70/80) encode the chip field as code plus a number.
CHIP_FAMILIES = {
    0x19: "RV1109/RV1126", 0x30: "PX30/RK3326", 0x32: "RK3562",
    0x33: "RK3399/RK3399Pro", 0x35: "RK3588/RK3588S", 0x36: "RK3326",
    0x38: "RK3566/RK3568", 0x39: "RK3528", 0x41: "RK3368", 0x48: "RK3308",
    0x50: "RK29xx", 0x51: "RV1108", 0x60: "RK30xx/RK3066",
    0x70: "RK31xx/RK3188", 0x80: "RK32xx/RK3288",
}
LEGACY_CHIPS = (0x50, 0x51, 0x60, 0x70, 0x80)


def echo(msg):
    """Write one line to the console.

    Args:
        msg: The text to print."""
    print(str(_log_tr(msg)))


def _pro_dir():
    """Return the project directory.

    Returns:
        str: The project directory when it exists, an empty string otherwise."""
    for key in ("WORK_PRO", "RNA_PRO", "DNA_PRO"):
        val = os.getenv(key)
        if val and os.path.isdir(val):
            return val
    return ""


def resolve_input(path):
    """Resolve an input path, looking it up by name in the project directory
    when needed.

    Args:
        path: The raw input path.

    Returns:
        str: The resolved absolute path, or the input when it is not found."""
    path = (path or "").strip().strip('"')
    if not path:
        return path
    if os.path.isfile(path) or os.path.isdir(path):
        return os.path.abspath(path)
    name = os.path.basename(path)
    roots = []
    pro = _pro_dir()
    if pro:
        roots.append(os.path.join(pro, "out"))
        roots.append(pro)
    for key in ("WORK_DRO", "RNA_DRO", "DNA_DRO"):
        val = os.getenv(key)
        if val:
            roots.append(val)
    roots.append(os.getcwd())
    for root in roots:
        cand = os.path.join(root, name)
        if os.path.isfile(cand):
            return os.path.abspath(cand)
    return path


_RKCRC32_TABLE = None


def _rkcrc32_table():
    """Build the Rockchip CRC32 lookup table lazily.

        The polynomial is 0x04C10DB7.

    Returns:
        list: The table with 256 entries."""
    global _RKCRC32_TABLE
    if _RKCRC32_TABLE is not None:
        return _RKCRC32_TABLE
    poly = 0x04C10DB7
    table = []
    for i in range(256):
        val = (i << 24) & 0xFFFFFFFF
        for _ in range(8):
            if val & 0x80000000:
                val = ((val << 1) ^ poly) & 0xFFFFFFFF
            else:
                val = (val << 1) & 0xFFFFFFFF
        table.append(val)
    _RKCRC32_TABLE = table
    return table


def rkcrc32(crc, data):
    """Update the CRC32 with the Rockchip polynomial.

    Args:
        crc: The current value.
        data: The bytes to compute over.

    Returns:
        int: The updated CRC32."""
    table = _rkcrc32_table()
    for byte in data:
        crc = ((crc << 8) ^ table[((crc >> 24) ^ byte) & 0xFF]) & 0xFFFFFFFF
    return crc


def rkcrc32_file(path):
    """Compute the Rockchip CRC32 of a file, starting at byte 4.

    Args:
        path: The file path.

    Returns:
        int: The CRC32."""
    crc = 0
    with open(path, "rb") as f:
        f.seek(4)
        for chunk in iter(lambda: f.read(CHUNK), b""):
            crc = rkcrc32(crc, chunk)
    return crc


def recover_true_size(stored, available):
    """Restore the real length from a 32 bit wrap field.

    Args:
        stored: The 32 bit value that is stored in the header.
        available: The amount of data that is there.

    Returns:
        int: The restored length, it can be above 4GiB."""
    stored = int(stored)
    if available <= stored:
        return stored
    return stored + (((available - stored) >> 32) << 32)


def _cstr(raw):
    """Turn a C style byte string into UTF-8 text.

    Args:
        raw: The raw bytes.

    Returns:
        str: The decoded text."""
    return raw.split(b"\x00", 1)[0].decode("utf-8", "replace")


def _fill_cstr_preserve_tail(field, value):
    """Write a string into a fixed size field.

        The bytes at the end of the field that are not overwritten stay as they are.

    Args:
        field: The fixed size buffer to write into.
        value: The string to write."""
    raw = value.encode("utf-8")[:len(field) - 1]
    field[:len(raw)] = raw
    field[len(raw)] = 0


def _copy_stream(rf, wf, length):
    """Copy a number of bytes from the source stream to the target stream.

    Args:
        rf: The source stream.
        wf: The target stream.
        length: The number of bytes to copy.

    Raises:
        OSError: When the source file ends early."""
    remain = length
    while remain > 0:
        piece = rf.read(min(CHUNK, remain))
        if not piece:
            raise OSError("The source file is truncated")
        wf.write(piece)
        remain -= len(piece)


def decode_chip_field(field):
    """Decode the 4 byte chip field into an RK number.

        The newer platforms store the four digits in reverse order.

    Args:
        field: The 4 byte chip field.

    Returns:
        str: A model such as RK3588, None when it is not recognised."""
    if all(0x30 <= b <= 0x39 for b in field):
        digits = "".join(chr(b) for b in reversed(field))
        return "RK" + digits
    return None


def chip_name_to_code(chip):
    """Map a chip name to its family code.

    Args:
        chip: The chip name.

    Returns:
        int: The family code, None when the chip is unknown."""
    name = (chip or "").upper()
    mapping = {
        "RV1109": 0x19, "RV1126": 0x19, "PX30": 0x30, "RK3562": 0x32,
        "RK3399": 0x33, "RK3399PRO": 0x33, "RK3588": 0x35, "RK3588S": 0x35,
        "RK3326": 0x36, "RK3566": 0x38, "RK3568": 0x38, "RK3528": 0x39,
        "RK3368": 0x41, "RK3308": 0x48, "RK29XX": 0x50, "RK29": 0x50,
        "RK2918": 0x50, "RK2908": 0x50, "RV1108": 0x51, "RK30XX": 0x60,
        "RK30": 0x60, "RK3066": 0x60, "RK3026": 0x60, "RK31XX": 0x70,
        "RK31": 0x70, "RK3188": 0x70, "PX1": 0x70, "PX3": 0x70, "PX4": 0x70,
        "RK32XX": 0x80, "RK32": 0x80, "RK3288": 0x80,
    }
    return mapping.get(name)


def encode_chip_field(chip):
    """Encode a chip name into the 4 byte field of the RKFW header.

    Args:
        chip: The chip name.

    Returns:
        bytes: The 4 byte field.

    Raises:
        ValueError: When the chip is not supported."""
    code = chip_name_to_code(chip)
    if code is None:
        raise ValueError("Unsupported chip: {}".format(chip))
    digits = [b for b in chip.encode("utf-8") if 0x30 <= b <= 0x39]
    if code not in LEGACY_CHIPS and len(digits) == 4:
        return bytes([digits[3], digits[2], digits[1], digits[0]])
    field = bytearray([code, 0, 0, 0])
    if len(digits) >= 3:
        field[1] = digits[2]
        field[2] = digits[1]
        field[3] = digits[0]
    return bytes(field)


def decode_chip(field_bytes):
    """Decode the chip field.

        When the number cannot be recognised the family name table is used.

    Args:
        field_bytes: The 4 byte chip field.

    Returns:
        str: The name of the chip."""
    decoded = decode_chip_field(field_bytes)
    if decoded:
        return decoded
    return CHIP_FAMILIES.get(field_bytes[0] if field_bytes else 0, "unknown")


def unpack_rkfw(src, out_dir):
    """Open the outer RKFW and write the header, the BOOT and the embedded
        update.img.

        The header holds the signature and the length, the version, the code, the
        time, the chip, the offset and the size of the BOOT and the offset and the
        size of the update; the file may end with a 32 byte ASCII MD5.

    Args:
        src: The path of the RKFW firmware.
        out_dir: The output directory.

    Raises:
        ValueError: When the header is too small or no embedded RKAF was found."""
    with open(src, "rb") as fp:
        buf = fp.read(RKFW_HEADER_SIZE)
        if len(buf) < RKFW_HEADER_SIZE:
            raise ValueError("The RKFW header is too small")
        filesize = os.path.getsize(src)
        version = "{}.{}.{}".format(buf[9], buf[8], (buf[7] << 8) + buf[6])
        code = struct.unpack_from("<I", buf, 0x0A)[0]
        year = (buf[0x0F] << 8) | buf[0x0E]
        date = "{:04}-{:02}-{:02} {:02}:{:02}:{:02}".format(
            year, buf[0x10], buf[0x11], buf[0x12], buf[0x13], buf[0x14])
        echo("> Version: {}".format(version))
        echo("> code: 0x{:08x}".format(code))
        echo("> Time: {}".format(date))
        echo("> Chip: {}".format(decode_chip(buf[0x15:0x19])))
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, "rkfw-header.bin"), "wb") as wf:
            wf.write(buf)
        boot_off = struct.unpack_from("<I", buf, 0x19)[0]
        boot_size = struct.unpack_from("<I", buf, 0x1D)[0]
        echo("> Extracted the BOOT ({} bytes)".format(boot_size))
        with open(os.path.join(out_dir, "BOOT"), "wb") as wf:
            fp.seek(boot_off)
            _copy_stream(fp, wf, boot_size)
        update_off = struct.unpack_from("<I", buf, 0x21)[0]
        stored_size = struct.unpack_from("<I", buf, 0x25)[0]
        fp.seek(update_off)
        if fp.read(4) != RKAF_SIGNATURE:
            raise ValueError("No embedded RKAF update.img was found")
        data_end = filesize
        if filesize >= update_off + 32:
            fp.seek(-32, os.SEEK_END)
            tail = fp.read(32)
            if all(chr(b) in "0123456789abcdefABCDEF" for b in tail):
                data_end = filesize - 32
        update_size = recover_true_size(stored_size, data_end - update_off)
        if update_size != stored_size:
            echo("> Note: the header size field is 0x{:08x}, the real size is restored to {} bytes (>4GiB wrap)".format(
                stored_size, update_size))
        echo("> Extracted the embedded-update.img ({} bytes)".format(update_size))
        with open(os.path.join(out_dir, "embedded-update.img"), "wb") as wf:
            fp.seek(update_off)
            _copy_stream(fp, wf, update_size)


def pack_rkfw(in_dir, out_file, chip=None, version=None, timestamp=None, code_hex=None):
    """Build an RKFW from the BOOT and the embedded-update.img of a
        directory.

        Without an rkfw-header.bin template the chip, version, timestamp and code
        have to be given; when the update is above 4GiB the header only holds the lower
        32 bits and the MD5 of the whole package is written at the end.

    Args:
        in_dir: The directory of the extraction.
        out_file: The path of the RKFW to write.
        chip: The chip name.
        version: The major.minor.build version.
        timestamp: The Unix timestamp.
        code_hex: The code field as hex text.

    Raises:
        ValueError: When the template is missing and the arguments are not complete
            or a required file is absent."""
    boot_path = os.path.join(in_dir, "BOOT")
    update_path = os.path.join(in_dir, "embedded-update.img")
    template_path = os.path.join(in_dir, "rkfw-header.bin")
    template = None
    if os.path.isfile(template_path):
        with open(template_path, "rb") as f:
            data = f.read()
        if len(data) >= RKFW_HEADER_SIZE:
            template = data[:RKFW_HEADER_SIZE]
    header = bytearray(template or bytes(RKFW_HEADER_SIZE))

    def missing(flag):
        """Report a missing required argument.

        Args:
            flag: The name of the argument.

        Raises:
            ValueError: Always."""
        raise ValueError("--{} is required (no rkfw-header.bin template in the directory)".format(flag))

    header[0:4] = RKFW_SIGNATURE
    header[0x04] = RKFW_HEADER_SIZE
    if version is not None:
        parts = version.split(".")
        if len(parts) != 3:
            raise ValueError("The version has to be major.minor.build (e.g. 8.1.0)")
        major, minor, build = int(parts[0]), int(parts[1]), int(parts[2])
        header[6] = build & 0xFF
        header[7] = (build >> 8) & 0xFF
        header[8] = minor
        header[9] = major
    elif template is None:
        missing("version")
    if code_hex is not None:
        struct.pack_into("<I", header, 0x0A, int(code_hex.strip().lstrip("0x0X") or "0", 16))
    elif template is None:
        missing("code")
    if timestamp is not None:
        import datetime
        dt = datetime.datetime.fromtimestamp(int(timestamp), datetime.timezone.utc).timetuple()
        header[0x0E] = dt.tm_year & 0xFF
        header[0x0F] = (dt.tm_year >> 8) & 0xFF
        header[0x10] = dt.tm_mon
        header[0x11] = dt.tm_mday
        header[0x12] = dt.tm_hour
        header[0x13] = dt.tm_min
        header[0x14] = dt.tm_sec
    elif template is None:
        missing("timestamp")
    if chip is not None:
        header[0x15:0x19] = encode_chip_field(chip)
    elif template is None:
        missing("chip")
    if template is None:
        header[0x2D] = 0x01
    if not os.path.isfile(boot_path):
        raise ValueError("The directory has no BOOT file")
    if not os.path.isfile(update_path):
        raise ValueError("The directory has no embedded-update.img file")
    boot_size = os.path.getsize(boot_path)
    update_size = os.path.getsize(update_path)
    if update_size < 4:
        raise ValueError("The embedded-update.img is not a valid RKAF file")
    with open(update_path, "rb") as f:
        if f.read(4) != RKAF_SIGNATURE:
            raise ValueError("The embedded-update.img is not a valid RKAF file")
    boot_off = RKFW_HEADER_SIZE
    update_off = boot_off + boot_size
    if boot_size > 0xFFFFFFFF or update_off > 0xFFFFFFFF:
        raise ValueError("The BOOT is too large ({} bytes)".format(boot_size))
    struct.pack_into("<I", header, 0x19, boot_off)
    struct.pack_into("<I", header, 0x1D, boot_size)
    struct.pack_into("<I", header, 0x21, update_off)
    struct.pack_into("<I", header, 0x25, update_size & 0xFFFFFFFF)
    if update_size > 0xFFFFFFFF:
        echo("> Note: update is {} bytes (>4GiB), the header holds the lower 32 bits".format(update_size))
    md5 = hashlib.md5()
    with open(out_file, "wb") as wf:
        wf.write(header)
        md5.update(header)
        with open(boot_path, "rb") as rf:
            for chunk in iter(lambda: rf.read(CHUNK), b""):
                wf.write(chunk)
                md5.update(chunk)
        with open(update_path, "rb") as rf:
            for chunk in iter(lambda: rf.read(CHUNK), b""):
                wf.write(chunk)
                md5.update(chunk)
        wf.write(md5.hexdigest().encode("ascii"))
    echo("> Image built: {} (BOOT {} bytes, update {} bytes, MD5: {})".format(
        out_file, boot_size, update_size, md5.hexdigest()))


def _update_part_decode(raw):
    """Parse a 112 byte RKAF partition entry.

    The layout is name(32) full_path(60) followed by flash_size, part_offset,
    flash_offset, padded_size and part_byte_count, four little endian bytes
    each.

    Args:
        raw: The 112 byte record.

    Returns:
        dict: The fields of the partition."""
    return {
        "name": _cstr(raw[0:32]),
        "full_path": _cstr(raw[32:92]),
        "flash_size": struct.unpack_from("<I", raw, 92)[0],
        "part_offset": struct.unpack_from("<I", raw, 96)[0],
        "flash_offset": struct.unpack_from("<I", raw, 100)[0],
        "padded_size": struct.unpack_from("<I", raw, 104)[0],
        "part_byte_count": struct.unpack_from("<I", raw, 108)[0],
    }


def decode_rkaf_header(buf):
    """Parse the 2048 byte RKAF header and its partition table.

        The header holds magic(4) length(4) model(34) id(30) manufacturer(56) and
        then unknown1, version and num_parts, followed by at most 16 partition
        entries of 112 bytes.

    Args:
        buf: The header bytes.

    Returns:
        dict: The header fields and the partitions.

    Raises:
        ValueError: When the header is too small, the magic is wrong or there are
            too many partitions."""
    if len(buf) < RKAF_HEADER_SIZE:
        raise ValueError("The RKAF header is too small")
    magic = buf[0:4]
    if magic != RKAF_SIGNATURE:
        raise ValueError("Invalid RKAF magic")
    header = {
        "magic": magic,
        "length": struct.unpack_from("<I", buf, 4)[0],
        "model": _cstr(buf[8:42]),
        "id": _cstr(buf[42:72]),
        "manufacturer": _cstr(buf[72:128]),
        "unknown1": struct.unpack_from("<I", buf, 128)[0],
        "version": struct.unpack_from("<I", buf, 132)[0],
        "num_parts": struct.unpack_from("<I", buf, 136)[0],
        "parts": [],
    }
    if header["num_parts"] > MAX_PARTS:
        raise ValueError("The partition count {} is above the limit {}".format(header["num_parts"], MAX_PARTS))
    for i in range(header["num_parts"]):
        header["parts"].append(_update_part_decode(buf[140 + i * 112:140 + (i + 1) * 112]))
    return header


def _update_part_encode(part):
    """Encode a partition dictionary into a 112 byte record.

    Args:
        part: The fields of the partition.

    Returns:
        bytearray: The encoded record."""
    raw = bytearray(112)
    _fill_cstr_preserve_tail(memoryview(raw)[0:32], part["name"])
    _fill_cstr_preserve_tail(memoryview(raw)[32:92], part["full_path"])
    struct.pack_into("<I", raw, 92, part["flash_size"])
    struct.pack_into("<I", raw, 96, part["part_offset"])
    struct.pack_into("<I", raw, 100, part["flash_offset"])
    struct.pack_into("<I", raw, 104, part["padded_size"])
    struct.pack_into("<I", raw, 108, part["part_byte_count"])
    return raw


def encode_rkaf_header(header):
    """Encode an RKAF header dictionary into a 2048 byte buffer.

    Args:
        header: The header fields and the partitions.

    Returns:
        bytes: The 2048 byte buffer."""
    buf = bytearray(RKAF_HEADER_SIZE)
    buf[0:4] = header["magic"]
    struct.pack_into("<I", buf, 4, header["length"] & 0xFFFFFFFF)
    _fill_cstr_preserve_tail(memoryview(buf)[8:42], header["model"])
    _fill_cstr_preserve_tail(memoryview(buf)[42:72], header["id"])
    _fill_cstr_preserve_tail(memoryview(buf)[72:128], header["manufacturer"])
    struct.pack_into("<I", buf, 128, header["unknown1"])
    struct.pack_into("<I", buf, 132, header["version"])
    struct.pack_into("<I", buf, 136, header["num_parts"])
    for i, part in enumerate(header["parts"]):
        buf[140 + i * 112:140 + (i + 1) * 112] = _update_part_encode(part)
    return bytes(buf)


def recover_partition_layout(header, container_end):
    """Restore the real layout of the partitions from the 32 bit offsets and
        sizes of the header.

        SELF and RESERVED (offset 0), the reuse of a path that appears twice and the
        wrap of the sizes above 4GiB are handled.

    Args:
        header: The RKAF header fields.
        container_end: The offset where the data of the container ends.

    Returns:
        list: The (offset, real length) pairs.

    Raises:
        ValueError: When a partition reaches past the container."""
    layout = []
    known = []
    previous_end = 0
    for part in header["parts"][:header["num_parts"]]:
        raw_offset = part["part_offset"]
        if raw_offset == 0:
            layout.append((0, part["part_byte_count"]))
            continue
        reused = None
        for (stored_off, stored_path, offset, true_count) in known:
            if stored_off == raw_offset and stored_path == part["full_path"]:
                reused = (offset, true_count)
                break
        if reused is not None:
            layout.append(reused)
            continue
        padded_bytes = part["padded_size"] * SECTOR_SIZE
        if padded_bytes:
            true_count = recover_true_size(part["part_byte_count"], padded_bytes)
            allocation_size = padded_bytes
        else:
            true_count = part["part_byte_count"]
            allocation_size = (true_count + SECTOR_SIZE - 1) // SECTOR_SIZE * SECTOR_SIZE
        offset = raw_offset
        if offset < previous_end:
            wraps = (previous_end - offset + U32_RANGE - 1) // U32_RANGE
            offset += wraps * U32_RANGE
        data_end = offset + true_count
        allocation_end = offset + allocation_size
        if data_end > container_end:
            raise ValueError(
                "The partition reaches past the container: offset {} size {} container_end {}".format(
                    offset, true_count, container_end))
        layout.append((offset, true_count))
        known.append((raw_offset, part["full_path"], offset, true_count))
        previous_end = allocation_end
    return layout


def _parm_content_range(name, fp, offset, length):
    """Compute the range of the content of the parameter partition, without
    the PARM header.

    Args:
        name: The partition name.
        fp: The firmware file object.
        offset: The offset of the partition.
        length: The length of the partition.

    Returns:
        tuple: (content offset, content length)."""
    if name != "parameter" or length < 12:
        return offset, length
    fp.seek(offset)
    header = fp.read(8)
    content_len = struct.unpack_from("<I", header, 4)[0]
    return offset + 8, content_len


def _parse_package_file(package_data):
    """Parse the text of the package-file.

    Args:
        package_data: The content of the file.

    Returns:
        list: The (name, path) pairs."""
    file_list = []
    for raw_line in package_data.split(b"\n"):
        line = raw_line.decode("utf-8", "replace").strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            file_list.append((parts[0], parts[1]))
    return file_list


def _parse_partition_metadata(in_dir):
    """Read the partition-metadata.txt that the unpack wrote.

    Args:
        in_dir: The directory of the extraction.

    Returns:
        dict: The metadata of every partition, an empty dictionary when the file
            is missing."""
    metadata = {}
    path = os.path.join(in_dir, "partition-metadata.txt")
    if not os.path.isfile(path):
        return metadata
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(",")
            if len(parts) >= 7:
                try:
                    metadata[parts[0]] = {
                        "full_path": parts[1],
                        "flash_size": int(parts[2], 16),
                        "flash_offset": int(parts[3], 16),
                    }
                except ValueError:
                    continue
    return metadata


def unpack_rkaf(src, out_dir):
    """Open an RKAF update.img.

    The header, the metadata and the partition files are written, SELF and
    RESERVED are not written to disk and the PARM wrapper is removed from the
    parameter partition.

    Args:
        src: The path of the RKAF image.
        out_dir: The output directory."""
    with open(src, "rb") as fp:
        buf = fp.read(RKAF_HEADER_SIZE)
        header = decode_rkaf_header(buf)
        filesize = os.path.getsize(src)
        container_end = filesize - 4
        if (container_end & 0xFFFFFFFF) != header["length"]:
            echo("> Note: the header.length field does not match, the CRC check is skipped")
        layout = recover_partition_layout(header, container_end)
        listing.print_partitions(
            [
                {
                    "name": part["name"],
                    "size": part["flash_size"],
                    "offset": part["flash_offset"],
                    "note": part["full_path"],
                }
                for part in header["parts"]
            ],
            title="Partitions",
        )
        os.makedirs(os.path.join(out_dir, "Image"), exist_ok=True)
        with open(os.path.join(out_dir, "rkaf-header.bin"), "wb") as wf:
            wf.write(buf)
        echo("> Vendor: {}  model: {}".format(header["manufacturer"], header["model"]))
        metadata_path = os.path.join(out_dir, "partition-metadata.txt")
        with open(metadata_path, "w", encoding="utf-8") as mf:
            for part in header["parts"]:
                mf.write("{},{},{:#010x},{:#010x},{:#010x},{:#010x},{:#010x}\n".format(
                    part["name"], part["full_path"], part["flash_size"],
                    part["flash_offset"], part["part_offset"],
                    part["padded_size"], part["part_byte_count"]))
        jobs = []
        for i, part in enumerate(header["parts"]):
            if part["full_path"] in ("SELF", "RESERVED"):
                continue
            file_to_extract = os.path.join(out_dir, part["full_path"])
            parent = os.path.dirname(file_to_extract)
            if parent and not os.path.isdir(parent):
                os.makedirs(parent, exist_ok=True)
            offset, true_count = layout[i]
            if offset != part["part_offset"]:
                echo("> Note: the offset of the partition {} is restored to 0x{:08x} -> {} (>4GiB wrap)".format(
                    part["name"], part["part_offset"], offset))
            if true_count != part["part_byte_count"]:
                echo("> Note: the size of the partition {} is restored to 0x{:08x} -> {} (>4GiB wrap)".format(
                    part["name"], part["part_byte_count"], true_count))
            data_offset, data_len = _parm_content_range(part["name"], fp, offset, true_count)
            echo("> Extracted {} ({} bytes)".format(part["full_path"], data_len))
            jobs.append((data_offset, data_len, file_to_extract))

    def work(job):
        """Extract a single partition.

        Args:
            job: (data offset, length, output path)."""
        data_offset, data_len, dest = job
        with open(src, "rb") as f, open(dest, "wb") as wf:
            f.seek(data_offset)
            _copy_stream(f, wf, data_len)

    threads = _extract_threads()
    if threads > 1 and len(jobs) > 1 and ThreadPoolExecutor is not None:
        with ThreadPoolExecutor(max_workers=min(threads, len(jobs))) as pool:
            list(pool.map(work, jobs))
    else:
        for job in jobs:
            work(job)
    echo("> Partition metadata: {}".format(metadata_path))


def _is_parm_blob(data):
    """Check whether a buffer already has the PARM wrapper.

    Args:
        data: The data to check.

    Returns:
        bool: True when the layout is signature, length, content and CRC."""
    if len(data) < 12 or data[:4] != PARM_SIGNATURE:
        return False
    content_len = struct.unpack_from("<I", data, 4)[0]
    return content_len == len(data) - 12


def _wrap_parm(raw_data):
    """Wrap the plain text of the parameter partition in the PARM struct.

    Args:
        raw_data: The raw content.

    Returns:
        bytes: PARM, length, content and CRC32, the input when it already has the
            wrapper."""
    if _is_parm_blob(raw_data):
        return raw_data
    wrapped = bytearray()
    wrapped += PARM_SIGNATURE
    wrapped += struct.pack("<I", len(raw_data))
    wrapped += raw_data
    wrapped += struct.pack("<I", rkcrc32(0, raw_data))
    return bytes(wrapped)


def pack_rkaf(in_dir, out_file, model, manufacturer):
    """Pack a directory into an RKAF with the package-file.

    Args:
        in_dir: The directory of the extraction.
        out_file: The path of the image to write.
        model: The model name.
        manufacturer: The manufacturer.

    Raises:
        ValueError: When the package-file is missing, the list is empty or there are
            too many partitions."""
    package_path = os.path.join(in_dir, "package-file")
    if not os.path.isfile(package_path):
        raise ValueError("The directory has no package-file")
    with open(package_path, "rb") as f:
        file_list = _parse_package_file(f.read())
    if not file_list:
        raise ValueError("The package-file holds no file entry")
    template_path = os.path.join(in_dir, "rkaf-header.bin")
    if os.path.isfile(template_path):
        with open(template_path, "rb") as f:
            template = decode_rkaf_header(f.read(RKAF_HEADER_SIZE))
    else:
        template = {
            "magic": RKAF_SIGNATURE, "length": 0, "model": "", "id": "",
            "manufacturer": "", "unknown1": 0, "version": 0x01000000,
            "num_parts": 0, "parts": [],
        }
    header = template
    header["magic"] = RKAF_SIGNATURE
    header["model"] = model
    header["manufacturer"] = manufacturer
    metadata = _parse_partition_metadata(in_dir)
    machine_id = ""
    for name, package_path_ in file_list:
        if name == "parameter":
            source = os.path.join(in_dir, package_path_.split("/")[-1])
            if metadata.get(name):
                source = os.path.join(in_dir, metadata[name]["full_path"])
            if os.path.isfile(source):
                with open(source, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if line.startswith("MACHINE_ID:"):
                            machine_id = line.split(":", 1)[1].strip()
                            break
            break
    if machine_id:
        header["id"] = machine_id
    else:
        header["id"] = ""
    data_start = (RKAF_HEADER_SIZE + SECTOR_SIZE - 1) // SECTOR_SIZE * SECTOR_SIZE
    current_offset = data_start
    write_list = []
    layout_map = {}
    emitted = 0
    for name, package_path_ in file_list:
        if package_path_ == "RESERVED":
            continue
        part_meta = metadata.get(name)
        header_path = part_meta["full_path"] if part_meta and part_meta["full_path"] else package_path_
        if package_path_ == "SELF":
            file_offset, file_size = 0, 0
        elif header_path in layout_map:
            file_offset, file_size = layout_map[header_path]
        else:
            source = os.path.join(in_dir, header_path)
            if not os.path.isfile(source):
                raise ValueError("The file was not found: {}".format(header_path))
            if name == "parameter":
                with open(source, "rb") as f:
                    wrapped = _wrap_parm(f.read())
                file_size = len(wrapped)
                write_list.append((source, wrapped, file_size))
            else:
                file_size = os.path.getsize(source)
                write_list.append((source, None, file_size))
            padded_size = (file_size + SECTOR_SIZE - 1) // SECTOR_SIZE * SECTOR_SIZE
            file_offset = current_offset
            layout_map[header_path] = (file_offset, file_size)
            current_offset += padded_size
        if emitted >= MAX_PARTS:
            raise ValueError("The package-file holds more partitions than the limit {}".format(MAX_PARTS))
        part = {
            "name": name,
            "full_path": header_path,
            "flash_size": part_meta["flash_size"] if part_meta else 0,
            "flash_offset": part_meta["flash_offset"] if part_meta else 0,
            "padded_size": (file_size + SECTOR_SIZE - 1) // SECTOR_SIZE if file_size else 0,
            "part_offset": file_offset & 0xFFFFFFFF,
            "part_byte_count": file_size & 0xFFFFFFFF,
        }
        header["parts"].append(part)
        emitted += 1
    header["num_parts"] = emitted
    header["length"] = current_offset & 0xFFFFFFFF
    encoded = encode_rkaf_header(header)
    crc = 0
    with open(out_file, "wb") as wf:
        wf.write(encoded)
        crc = rkcrc32(crc, encoded)
        pad = data_start - RKAF_HEADER_SIZE
        if pad > 0:
            wf.write(b"\x00" * pad)
            crc = rkcrc32(crc, b"\x00" * pad)
        for source, prebuilt, file_size in write_list:
            if prebuilt is not None:
                wf.write(prebuilt)
                crc = rkcrc32(crc, prebuilt)
            else:
                with open(source, "rb") as rf:
                    for chunk in iter(lambda: rf.read(CHUNK), b""):
                        wf.write(chunk)
                        crc = rkcrc32(crc, chunk)
            padded_size = (file_size + SECTOR_SIZE - 1) // SECTOR_SIZE * SECTOR_SIZE
            padding = padded_size - file_size
            if padding > 0:
                wf.write(b"\x00" * padding)
                crc = rkcrc32(crc, b"\x00" * padding)
        wf.write(struct.pack("<I", crc))
    echo("> Image built: {} ({} partitions, {} bytes, CRC32: 0x{:08x})".format(
        out_file, emitted, current_offset, crc))




def run_rkfw(args):
    """Run the firmware handling from an argparse namespace.

    Args:
        args: The parsed arguments with the action, file and out fields."""
    action = (getattr(args, "action", "") or "").strip().lower()
    try:
        if action in ("unpack", "extract"):
            src = resolve_input(getattr(args, "file", ""))
            if not src or not os.path.isfile(src):
                echo("> Not found: {}".format(src or "<empty>"))
                return
            out = (getattr(args, "out", "") or "").strip()
            if not out:
                base = os.path.splitext(os.path.basename(src))[0]
                out = os.path.join(_pro_dir() or os.path.dirname(src), base + "_rk")
            out = os.path.abspath(out)
            if os.path.isdir(out):
                shutil.rmtree(out)
            with open(src, "rb") as f:
                magic = f.read(4)
            echo("> Start the extraction: {} <{}>".format(os.path.basename(src), magic.decode("latin-1")))
            if magic == RKFW_SIGNATURE:
                unpack_rkfw(src, out)
            elif magic == RKAF_SIGNATURE:
                unpack_rkaf(src, out)
            else:
                echo("> Unsupported format: {} <rkfw>".format(os.path.basename(src)))
                return
            echo("> Extraction complete, files are in: {}".format(out))
        elif action in ("pack-rkfw", "pack_rkfw"):
            in_dir = resolve_input(getattr(args, "file", ""))
            if not in_dir or not os.path.isdir(in_dir):
                echo("> The directory does not exist: {}".format(in_dir or "<empty>"))
                return
            out = (getattr(args, "out", "") or "").strip() or os.path.join(
                os.path.dirname(in_dir.rstrip("\\/")), os.path.basename(in_dir.rstrip("\\/")) + ".img")
            out = os.path.abspath(out)
            echo("> Start the build: {} <rkfw>".format(os.path.basename(in_dir)))
            pack_rkfw(in_dir, out,
                      chip=getattr(args, "chip", "") or None,
                      version=getattr(args, "version", "") or None,
                      timestamp=int(getattr(args, "timestamp", 0) or 0) or None,
                      code_hex=getattr(args, "code", "") or None)
        elif action in ("pack-rkaf", "pack_rkaf"):
            in_dir = resolve_input(getattr(args, "file", ""))
            if not in_dir or not os.path.isdir(in_dir):
                echo("> The directory does not exist: {}".format(in_dir or "<empty>"))
                return
            out = (getattr(args, "out", "") or "").strip() or os.path.join(
                os.path.dirname(in_dir.rstrip("\\/")), os.path.basename(in_dir.rstrip("\\/")) + ".img")
            out = os.path.abspath(out)
            model = getattr(args, "model", "") or ""
            manufacturer = getattr(args, "manufacturer", "") or ""
            if not model or not manufacturer:
                echo("> --model and --manufacturer are required")
                return
            echo("> Start the build: {} <rkaf>".format(os.path.basename(in_dir)))
            pack_rkaf(in_dir, out, model, manufacturer)
        else:
            echo("> Unsupported: {} <action, one of unpack/pack-rkfw/pack-rkaf>".format(action))
            return
    except Exception as exc:
        debug_exc("rkfw failed: ")
        echo("> Processing the Rockchip firmware failed: {}".format(exc))
        return


def parse_argv(argv):
    """Parse the rkfw command line arguments.

    Args:
        argv: The argument list without the program name.

    Returns:
        Namespace: The parsed arguments."""
    p = argparse.ArgumentParser(prog="rkfw", description="Unpack / pack RockChip firmware images (RKFW / RKAF)")
    p.add_argument("action", help="unpack | pack-rkfw | pack-rkaf")
    p.add_argument("file", help="Firmware file (unpack) or directory (pack)")
    p.add_argument("out", nargs="?", default="", help="Output directory (unpack) or image file (pack)")
    p.add_argument("--chip", default="", help="Chip name, e.g. RK3588 / RK3566 / PX30 (pack-rkfw)")
    p.add_argument("--version", default="", help="Version major.minor.build (pack-rkfw)")
    p.add_argument("--timestamp", type=int, default=0, help="Unix timestamp for build date (pack-rkfw)")
    p.add_argument("--code", default="", help="Code field as hex, e.g. 0x02000000 (pack-rkfw)")
    p.add_argument("--model", default="", help="Model name (pack-rkaf)")
    p.add_argument("--manufacturer", default="", help="Manufacturer name (pack-rkaf)")
    p.add_argument("--debug", action="store_true", help="Enable debug output")
    return p.parse_args(argv)


def main(argv=None):
    """The command line entry point.

    Args:
        argv: The argument list, sys.argv by default."""
    args = parse_argv(sys.argv[1:] if argv is None else argv)
    try:
        from .log import apply_args as _apply
        _apply(args)
    except Exception:
        if getattr(args, "debug", False):
            from .log import set_debug
            set_debug(True)
    run_rkfw(args)


if __name__ == "__main__":
    main()
