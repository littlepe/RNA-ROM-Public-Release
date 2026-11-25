#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unpack, pack, convert and verify AMLogic images (v1/v2).

The 64 byte file header and the entry table are parsed to pick up the
PARTITION, USB and config entries; packing writes the data area with the
requested alignment, appends a sha1sum VERIFY and finally fills in the CRC32."""

from __future__ import print_function

import argparse
import hashlib
import os
import re
import shutil
import struct
import sys
import zlib

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
# AMLogic image magic 0x27B51956; entry type 0=plain, 254=sparse.
MAGIC = 0x27B51956
FILE_TYPE_GENERIC = 0
FILE_TYPE_SPARSE = 254
SPARSE_MAGIC = b"\x3a\xff\x26\xed"
# The 64 byte header: crc/version/magic/image_size/align/count/reserve(36).
HEADER_FMT = "<IIIQII36s"
HEADER_SIZE = 64
# A v1 entry is 128 bytes (name 32), a v2 entry is 576 bytes (name 256).
ENTRY_FMT = {1: "<IIQQQ32s32sIHH24s", 2: "<IIQQQ256s256sIHH24s"}
ENTRY_SIZE = {1: 128, 2: 576}
TYPE_LEN = {1: 32, 2: 256}
USB_STEMS = ("DDR", "DDR_ENC", "UBOOT", "UBOOT_ENC")
ESSENTIALS = (("aml_sdc_burn", "ini"), ("meson1", "dtb"), ("platform", "conf"))


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


def _align_up(value, align):
    """Round a value up to the next multiple.

    Args:
        value: The raw value.
        align: The alignment.

    Returns:
        int: The aligned value."""
    return (value + align - 1) // align * align


def ampack_crc32(data):
    """Compute the CRC32 of an AMLogic image.

    The same as a zlib CRC with the result inverted.

    Args:
        data: The bytes to compute over.

    Returns:
        int: The CRC32."""
    return zlib.crc32(data) ^ 0xFFFFFFFF


def file_crc32(path):
    """Compute the image CRC32 of a file, starting at byte 4.

    Args:
        path: The file path.

    Returns:
        int: The CRC32."""
    crc = 0
    with open(path, "rb") as f:
        f.seek(4)
        for chunk in iter(lambda: f.read(CHUNK), b""):
            crc = zlib.crc32(chunk, crc)
    return crc ^ 0xFFFFFFFF


def sha1_of_range(f, offset, size):
    """Compute the SHA1 of a range inside a stream.

    Args:
        f: The binary stream.
        offset: The start offset.
        size: The length.

    Returns:
        bytes: The SHA1 digest.

    Raises:
        OSError: When the stream ends before the range is read."""
    hasher = hashlib.sha1()
    f.seek(offset)
    remain = size
    while remain > 0:
        piece = f.read(min(CHUNK, remain))
        if not piece:
            raise OSError("unexpected EOF while hashing")
        hasher.update(piece)
        remain -= len(piece)
    return hasher.digest()


def _cstr(raw):
    """Turn a C style byte string into UTF-8 text.

    Args:
        raw: The raw bytes.

    Returns:
        str: The decoded text."""
    return raw.split(b"\x00", 1)[0].decode("utf-8", "replace")


def _fill_cstr(text, length):
    """Encode text into a fixed length field padded with NUL.

    Args:
        text: The text.
        length: The length of the field.

    Returns:
        bytes: The fixed length bytes."""
    raw = (text or "").encode("utf-8")[:length - 1]
    return raw + b"\x00" * (length - len(raw))


def read_header(f):
    """Read and check the 64 byte image header.

    Args:
        f: The binary stream.

    Returns:
        dict: The header fields.

    Raises:
        ValueError: When the image is too small, the magic does not match or the
            version is not supported."""
    f.seek(0)
    hdr = f.read(HEADER_SIZE)
    if len(hdr) < HEADER_SIZE:
        raise ValueError("The image is too small to be an AMLogic image")
    crc, version, magic, image_size, align, count, _reserve = \
        struct.unpack(HEADER_FMT, hdr)
    if magic != MAGIC:
        raise ValueError("The magic does not match: expected 0x{:08x}, got 0x{:08x}".format(MAGIC, magic))
    if version not in (1, 2):
        raise ValueError("Unsupported image version: {}".format(version))
    return {"crc": crc, "version": version, "image_size": image_size,
            "align": align, "count": count}


def read_entries(f, hdr):
    """Read the entry table and merge every PARTITION with the VERIFY that
        follows it.

        Entry fields: id/type/offset/size/main/sub/verify/is_backup/backup_id;
        a PARTITION has to be followed by a VERIFY of the same name (48 bytes,
        ``sha1sum <hex>``).

    Args:
        f: The binary stream.
        hdr: The header fields returned by read_header.

    Returns:
        list: The entries.

    Raises:
        ValueError: When the entry table is truncated or a VERIFY is missing or out
            of place."""
    version = hdr["version"]
    fmt = ENTRY_FMT[version]
    size = ENTRY_SIZE[version]
    entries = []
    pending = None
    for item_id in range(hdr["count"]):
        f.seek(HEADER_SIZE + size * item_id)
        raw = f.read(size)
        if len(raw) < size:
            raise ValueError("The entry table is truncated: {}".format(item_id))
        (_iid, file_type, _cur, offset_in_image, item_size,
         main_raw, sub_raw, verify, is_backup, backup_id, _res) = struct.unpack(fmt, raw)
        entry = {
            "item_id": item_id,
            "file_type": file_type,
            "offset": offset_in_image,
            "size": item_size,
            "main": _cstr(main_raw),
            "sub": _cstr(sub_raw),
            "verify": verify,
            "is_backup": is_backup,
            "backup_id": backup_id,
            "sha1": None,
        }
        if pending is not None:
            if entry["sub"] != pending["sub"] or entry["main"] != "VERIFY":
                raise ValueError("The VERIFY of the partition {} is missing or out of place".format(pending["sub"]))
            f.seek(entry["offset"])
            vdata = f.read(entry["size"])
            if entry["size"] != 48 or not vdata.startswith(b"sha1sum ") or entry["verify"] != 0:
                raise ValueError("The VERIFY of the partition {} is malformed".format(pending["sub"]))
            pending["sha1"] = bytes.fromhex(vdata[8:48].decode("ascii"))
            entries.append(pending)
            pending = None
            continue
        if entry["main"] == "PARTITION":
            if entry["verify"] == 0:
                raise ValueError("The partition {} has no VERIFY".format(entry["sub"]))
            pending = entry
            continue
        if entry["verify"] != 0:
            raise ValueError("The entry {}.{} must not carry a VERIFY marker".format(entry["sub"], entry["main"]))
        entries.append(entry)
    if pending is not None:
        raise ValueError("The last partition {} has no VERIFY".format(pending["sub"]))
    return entries


def verify_image(src, quiet=False):
    """Check the SHA1 of every partition recorded in the image.

    Args:
        src: The image path.
        quiet: Keep the per entry output quiet.

    Returns:
        tuple: (header fields, entries).

    Raises:
        ValueError: When the SHA1 of a partition does not match."""
    with open(src, "rb") as f:
        hdr = read_header(f)
        entries = read_entries(f, hdr)
        ok = True
        for entry in entries:
            if entry["sha1"] is None:
                continue
            actual = sha1_of_range(f, entry["offset"], entry["size"])
            name = "{}.{}".format(entry["sub"], entry["main"])
            if actual == entry["sha1"]:
                echo("> Check passed: {}".format(name))
            else:
                echo("> Check failed: {} (recorded={} actual={})".format(
                    name, entry["sha1"].hex(), actual.hex()))
                ok = False
    if not ok:
        raise ValueError("The SHA1 of the image does not match")
    return hdr, entries


def _print_entries(entries):
    """Print a summary of the entries.

    Args:
        entries: The entry list."""
    listing.print_partitions(
        [
            {
                "name": "{}.{}".format(entry["sub"], entry["main"]),
                "size": entry["size"],
                "offset": entry["offset"],
                "type": entry["file_type"],
                "note": "sha1={}".format(entry["sha1"].hex()) if entry["sha1"] else "",
            }
            for entry in entries
        ],
        title="Entries",
        stream=sys.stdout,
    )


def unpack_image(src, out_dir, no_verify=False):
    """Extract the entries of an image as ``sub.main`` files.

    Args:
        src: The image path.
        out_dir: The output directory.
        no_verify: Skip the SHA1 check.
        auto: Non zero keeps unpacking the images that were found.

    Raises:
        ValueError: When the SHA1 check fails."""
    os.makedirs(out_dir, exist_ok=True)
    with open(src, "rb") as f:
        hdr = read_header(f)
        echo("> Image: v{}, align {}, {} entries".format(hdr["version"], hdr["align"], hdr["count"]))
        entries = read_entries(f, hdr)
        if not no_verify:
            for entry in entries:
                if entry["sha1"] is None:
                    continue
                actual = sha1_of_range(f, entry["offset"], entry["size"])
                if actual != entry["sha1"]:
                    raise ValueError("The SHA1 of the partition {} does not match".format(entry["sub"]))
            echo("> Every partition passed the SHA1 check")
        jobs = []
        for entry in entries:
            name = "{}.{}".format(entry["sub"], entry["main"])
            dst = os.path.join(out_dir, name)
            echo("> Extracted {} ({} bytes)".format(name, entry["size"]))
            jobs.append((name, entry["offset"], entry["size"], dst))

    def work(job):
        """Extract a single entry.

        Args:
            job: (name, offset, length, output path)."""
        name, offset, size, dst = job
        with open(src, "rb") as f, open(dst, "wb") as wf:
            f.seek(offset)
            remain = size
            while remain > 0:
                piece = f.read(min(CHUNK, remain))
                if not piece:
                    raise OSError("The image data is truncated: {}".format(name))
                wf.write(piece)
                remain -= len(piece)

    threads = _extract_threads()
    if threads > 1 and len(jobs) > 1 and ThreadPoolExecutor is not None:
        with ThreadPoolExecutor(max_workers=min(threads, len(jobs))) as pool:
            list(pool.map(work, jobs))
    else:
        for job in jobs:
            work(job)
    echo("> Extraction complete, files are in: {}".format(out_dir))




def _scan_dir(in_dir):
    """Scan the source directory of a pack and sort the entries.

    The required USB and config entries are checked on the way.

    Args:
        in_dir: The source directory.

    Returns:
        list: The sorted entries.

    Raises:
        ValueError: When the directory is missing, a USB entry is invalid or a
            required file is absent."""
    if not os.path.isdir(in_dir):
        raise ValueError("The directory does not exist: {}".format(in_dir))
    usb = {}
    generic = []
    for name in sorted(os.listdir(in_dir)):
        path = os.path.join(in_dir, name)
        if not os.path.isfile(path) or "." not in name:
            continue
        stem, ext = name.split(".", 1)
        if ext == "USB":
            if stem not in USB_STEMS:
                raise ValueError("Unsupported USB entry: {}".format(name))
            if stem in usb:
                raise ValueError("Duplicate USB entry: {}".format(name))
            usb[stem] = path
            continue
        generic.append({"stem": stem, "ext": ext, "path": path})
    for stem in ("DDR", "UBOOT"):
        if stem not in usb:
            raise ValueError("The required file is missing: {}.USB".format(stem))
    have = {(g["stem"], g["ext"]) for g in generic}
    for stem, ext in ESSENTIALS:
        if (stem, ext) not in have:
            raise ValueError("The required file is missing: {}.{}".format(stem, ext))
    ordered = []
    for stem in USB_STEMS:
        if stem in usb:
            ordered.append({"stem": stem, "ext": "USB", "path": usb[stem]})
    ordered.extend(sorted(generic, key=lambda g: (g["stem"], g["ext"])))
    return ordered


def _fill_item_info(item, f):
    """Fill in the size, the file_type and the SHA1 of an entry.

    Args:
        item: The entry dictionary.
        f: The source stream, unused for now and kept for the callers.

    Raises:
        OSError: When the source file is truncated."""
    if "size" not in item or not item["size"]:
        item["size"] = os.path.getsize(item["path"])
    size = item["size"]
    with open(item["path"], "rb") as rf:
        rf.seek(item.get("src_off", 0))
        head = rf.read(4)
        item["file_type"] = FILE_TYPE_SPARSE if head == SPARSE_MAGIC else FILE_TYPE_GENERIC
        hasher = hashlib.sha1()
        rf.seek(item.get("src_off", 0))
        remain = size
        while remain > 0:
            piece = rf.read(min(CHUNK, remain))
            if not piece:
                raise OSError("The source file is truncated: {}".format(item["path"]))
            hasher.update(piece)
            remain -= len(piece)
    item["sha1"] = hasher.digest()


def _plan_items(items, align):
    """Plan the layout of the data area.

    Backup entries that share a SHA1 are reused and a VERIFY is inserted for
    every PARTITION.

    Args:
        items: The source entries.
        align: The alignment.

    Returns:
        tuple: (entry info list, data area size)."""
    infos = []
    body_len = 0
    sha1_index = []
    for item in items:
        is_backup = 0
        backup_id = 0
        body_off = 0
        for (sha1, idx, off, main, sub) in sha1_index:
            if sha1 == item["sha1"] and not (main == "USB" and sub.endswith("_ENC")):
                is_backup = 1
                backup_id = idx
                body_off = off
                break
        if not is_backup:
            body_off = _align_up(body_len, align)
            body_len = body_off + item["size"]
        infos.append({
            "file_type": item["file_type"],
            "body_off": body_off,
            "size": item["size"],
            "main": item["ext"],
            "sub": item["stem"],
            "verify": 1 if item["ext"] == "PARTITION" else 0,
            "is_backup": is_backup,
            "backup_id": backup_id,
            "sha1": item["sha1"],
        })
        sha1_index.append((item["sha1"], len(infos) - 1, body_off,
                           item["ext"], item["stem"]))
        if item["ext"] == "PARTITION":
            v_off = body_len
            vbytes = b"sha1sum " + item["sha1"].hex().encode()
            infos.append({
                "file_type": FILE_TYPE_GENERIC,
                "body_off": v_off,
                "size": len(vbytes),
                "main": "VERIFY",
                "sub": item["stem"],
                "verify": 0,
                "is_backup": is_backup,
                "backup_id": backup_id + 1 if is_backup else 0,
            })
            sha1_index.append((hashlib.sha1(vbytes).digest(), len(infos) - 1, v_off,
                               "VERIFY", item["stem"]))
            body_len = v_off + len(vbytes)
    return infos, body_len


def _sha1_for_verify(infos, verify_info):
    """Find the SHA1 of the PARTITION a VERIFY belongs to.

    Args:
        infos: The entry info list.
        verify_info: The info of the VERIFY entry.

    Returns:
        bytes: The SHA1 of the matching partition.

    Raises:
        ValueError: When no partition matches."""
    for info in infos:
        if info["main"] == "PARTITION" and info["sub"] == verify_info["sub"]:
            return info["sha1"]
    raise ValueError("VERIFY has no matching partition: {}".format(verify_info["sub"]))


def _item_for_info(items, info):
    """Find the source entry by stem and extension.

    Args:
        items: The source entries.
        info: The entry info.

    Returns:
        dict: The matching source entry.

    Raises:
        ValueError: When no source entry matches."""
    for item in items:
        if item["stem"] == info["sub"] and item["ext"] == info["main"]:
            return item
    raise ValueError("No source for the entry: {}.{}".format(info["sub"], info["main"]))


def _write_image(out_file, version, align, items):
    """Write the image following the plan.

    The header, the entry table and the data area are written and the CRC32 is
    filled in at the end.

    Args:
        out_file: The path of the image to write.
        version: The image version (1/2).
        align: The alignment.
        items: The source entries.

    Returns:
        tuple: (CRC32, entry count).

    Raises:
        ValueError: When the output size does not match the plan."""
    infos, body_len = _plan_items(items, align)
    count = len(infos)
    offset_base = HEADER_SIZE + ENTRY_SIZE[version] * count
    image_size = offset_base + body_len
    hdr = bytearray(struct.pack(
        HEADER_FMT, 0, version, MAGIC, image_size, align, count, b"\x00" * 36))
    fmt = ENTRY_FMT[version]
    type_len = TYPE_LEN[version]
    table = bytearray()
    for idx, info in enumerate(infos):
        table += struct.pack(
            fmt, idx, info["file_type"], 0, offset_base + info["body_off"],
            info["size"], _fill_cstr(info["main"], type_len),
            _fill_cstr(info["sub"], type_len), info["verify"],
            info["is_backup"], info["backup_id"], b"\x00" * 24)
    with open(out_file, "wb") as wf:
        wf.write(hdr)
        wf.write(table)
        cur = offset_base
        for info in infos:
            target = offset_base + info["body_off"]
            if info["main"] == "VERIFY":
                if target > cur:
                    wf.seek(cur)
                    wf.write(b"\x00" * (target - cur))
                    cur = target
                vbytes = b"sha1sum " + _sha1_for_verify(infos, info).hex().encode()
                wf.write(vbytes)
                cur += len(vbytes)
                continue
            if info["is_backup"]:
                continue
            if target > cur:
                wf.seek(cur)
                wf.write(b"\x00" * (target - cur))
                cur = target
            item = _item_for_info(items, info)
            with open(item["path"], "rb") as rf:
                rf.seek(item.get("src_off", 0))
                remain = item["size"]
                while remain > 0:
                    piece = rf.read(min(CHUNK, remain))
                    if not piece:
                        raise OSError("The source data is truncated: {}".format(item["path"]))
                    wf.write(piece)
                    remain -= len(piece)
            cur += item["size"]
        wf.truncate(image_size)
        wf.flush()
    crc = file_crc32(out_file)
    with open(out_file, "r+b") as wf:
        wf.seek(0)
        wf.write(struct.pack("<I", crc))
    actual = os.path.getsize(out_file)
    if actual != image_size:
        raise ValueError("The output size does not match: expected {}, got {}".format(image_size, actual))
    return crc, count


def pack_dir(in_dir, out_file, version, align, verify_out=False):
    """Pack a directory into an AMLogic image.

    Args:
        in_dir: The source directory.
        out_file: The path of the image to write.
        version: The image version (1/2).
        align: The alignment.
        verify_out: Check the image after it was written."""
    items = _scan_dir(in_dir)
    echo("> {} source files in total".format(len(items)))
    for item in items:
        _fill_item_info(item, None)
        echo("> Packed {}.{} ({} bytes)".format(item["stem"], item["ext"], item["size"]))
    crc, count = _write_image(out_file, version, align, items)
    echo("> Image built: {} (v{}, {} entries, CRC32: 0x{:08x})".format(
        out_file, version, count, crc))
    if verify_out:
        _verify_out(out_file)


def convert_image(src, out_file, version, align, no_verify=False, verify_out=False):
    """Rewrite an existing image with another version and alignment.

    Args:
        src: The source image path.
        out_file: The path of the image to write.
        version: The target version (1/2).
        align: The alignment.
        no_verify: Skip the SHA1 check of the source image.
        verify_out: Check the image after it was written.

    Raises:
        ValueError: When the source image fails the check or an entry is missing."""
    with open(src, "rb") as f:
        hdr = read_header(f)
        entries = read_entries(f, hdr)
        echo("> Source image: v{}, align {}, {} entries".format(hdr["version"], hdr["align"], len(entries)))
        if not no_verify:
            for entry in entries:
                if entry["sha1"] is None:
                    continue
                actual = sha1_of_range(f, entry["offset"], entry["size"])
                if actual != entry["sha1"]:
                    raise ValueError("The SHA1 of the partition {} does not match".format(entry["sub"]))
            echo("> The SHA1 of the source image passed the check")
        items = []
        for entry in entries:
            item = {
                "stem": entry["sub"],
                "ext": entry["main"],
                "path": src,
                "src_off": entry["offset"],
                "size": entry["size"],
                "sha1": entry["sha1"],
                "file_type": entry["file_type"],
            }
            if item["sha1"] is None:
                _fill_item_info(item, f)
            items.append(item)
    ordered = []
    usb_items = {}
    generic = []
    for item in items:
        if item["ext"] == "USB":
            if item["stem"] not in USB_STEMS:
                raise ValueError("Unsupported USB entry: {}".format(item["stem"]))
            if item["stem"] in usb_items:
                raise ValueError("Duplicate USB entry: {}".format(item["stem"]))
            usb_items[item["stem"]] = item
            continue
        generic.append(item)
    for stem in ("DDR", "UBOOT"):
        if stem not in usb_items:
            raise ValueError("The source image has no {}.USB".format(stem))
    for stem in USB_STEMS:
        if stem in usb_items:
            ordered.append(usb_items[stem])
    ordered.extend(sorted(generic, key=lambda g: (g["stem"], g["ext"])))
    crc, count = _write_image(out_file, version, align, ordered)
    echo("> Image converted: {} (v{}, {} entries, CRC32: 0x{:08x})".format(
        out_file, version, count, crc))
    if verify_out:
        _verify_out(out_file)


def _verify_out(out_file):
    """Check the image that was just written.

    Args:
        out_file: The image path.

    Raises:
        ValueError: When the check fails."""
    try:
        verify_image(out_file)
        echo("> The output image passed the check")
    except Exception as exc:
        raise ValueError("The output image failed the check: {}".format(exc))


def crc32_image(src):
    """Compare the CRC stored in the header with a fresh computation.

    Args:
        src: The image path.

    Returns:
        tuple: (recorded CRC32, computed CRC32)."""
    with open(src, "rb") as f:
        recorded = struct.unpack("<I", f.read(4))[0]
    computed = file_crc32(src)
    echo("> Image CRC32 recorded: 0x{:08x}".format(recorded))
    echo("> Computed CRC32:   0x{:08x}".format(computed))
    return recorded, computed


def run_ampack(args):
    """Run the image handling from an argparse namespace.

    Args:
        args: The parsed arguments with the action, file and out fields."""
    action = (getattr(args, "action", "") or "").strip().lower()
    src = resolve_input(getattr(args, "file", ""))
    if not src or not (os.path.isfile(src) or os.path.isdir(src)):
        echo("> Not found: {}".format(src or "<empty>"))
        return
    out = getattr(args, "out", "") or ""
    version = 1 if (getattr(args, "out_ver", "") or "v2").lower() == "v1" else 2
    align = int(getattr(args, "out_align", 4) or 4)
    if align % 4:
        align = (align + 3) // 4 * 4
    try:
        if action == "verify":
            echo("> Start the check: {} <ampack>".format(os.path.basename(src)))
            verify_image(src)
            echo("> Check complete")
        elif action == "unpack":
            if not out:
                out = os.path.join(_pro_dir() or os.path.dirname(src),
                                   os.path.splitext(os.path.basename(src))[0] + "_ampack")
            out = os.path.abspath(out)
            echo("> Start the extraction: {} <ampack>".format(os.path.basename(src)))
            if os.path.isdir(out):
                shutil.rmtree(out)
            unpack_image(src, out, no_verify=bool(int(getattr(args, "no_verify", 0) or 0)),
                         )
        elif action == "convert":
            if not out:
                out = os.path.splitext(src)[0] + "_converted.img"
            out = os.path.abspath(out)
            echo("> Start the conversion: {} <ampack> (v{} -> {})".format(
                os.path.basename(src), version, "v{}".format(version)))
            convert_image(src, out, version, align,
                          no_verify=bool(int(getattr(args, "no_verify", 0) or 0)),
                          verify_out=bool(int(getattr(args, "verify_out", 0) or 0)))
        elif action == "pack":
            if not out:
                out = os.path.join(os.path.dirname(src.rstrip("\\/")) or ".",
                                   os.path.basename(src.rstrip("\\/")) + ".img")
            out = os.path.abspath(out)
            echo("> Start the build: {} <ampack> (v{}, align {})".format(
                os.path.basename(src), version, align))
            pack_dir(src, out, version, align,
                     verify_out=bool(int(getattr(args, "verify_out", 0) or 0)))
        elif action == "crc32":
            recorded, computed = crc32_image(src)
            if recorded != computed:
                echo("> Warning: the CRC32 does not match! ! ! ")
            else:
                echo("> The CRC32 matches")
        else:
            echo("> Unsupported: {} <action, one of verify/unpack/convert/pack/crc32>".format(action))
            return
    except Exception as exc:
        debug_exc("ampack failed: ")
        echo("> Image processing failed: {}".format(exc))
        return


def parse_argv(argv):
    """Parse the ampack command line arguments.

    Args:
        argv: The argument list without the program name.

    Returns:
        Namespace: The parsed arguments."""
    p = argparse.ArgumentParser(prog="ampack", description="Unpack / pack / convert AMLogic burning images (v1/v2)")
    p.add_argument("action", help="verify | unpack | convert | pack | crc32")
    p.add_argument("file", help="Image file, or directory for pack")
    p.add_argument("out", nargs="?", default="", help="Output directory (unpack) or image file (convert/pack)")
    p.add_argument("--out-ver", dest="out_ver", default="v2", help="Output image version: v1 / v2 (convert/pack, default v2)")
    p.add_argument("--out-align", dest="out_align", type=int, default=4, help="Item alignment in bytes, multiply of 4 (convert/pack, default 4)")
    p.add_argument("--no-verify", dest="no_verify", type=int, default=0, help="Skip verification of input (default is 0)")
    p.add_argument("--verify-out", dest="verify_out", type=int, default=0, help="Verify output image after write (default is 0)")
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
    run_ampack(args)


if __name__ == "__main__":
    main()
