#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unpack the FIH and Nokia .nb0 firmware.

The partition table is parsed and the images are extracted by their offsets;
the partitions can be listed and the images can be unpacked further."""

from __future__ import print_function

import argparse
import os
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
PART_HEADER_FMT = "<IIII48s"
PART_HEADER_SIZE = struct.calcsize(PART_HEADER_FMT)

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




def _pro_dir():
    """Return the current project directory.

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


def _cstr(raw):
    """Cut a fixed size byte string at the NUL and decode it.

    Args:
        raw: The raw bytes.

    Returns:
        str: The decoded name."""
    return raw.split(b"\x00", 1)[0].decode("utf-8", "replace")


def detect_nb0(path):
    """Check whether the file is a valid .nb0 firmware.

    The number of partitions, the size of the table and whether the last
    partition ends at the size of the file decide it.

        Args:
            path: The file to check.

        Returns:
            bool: True when it is valid, False when it cannot be read."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            head = f.read(4)
            if len(head) < 4:
                return False
            count = struct.unpack("<I", head)[0]
            if count == 0 or count > 0x10000:
                return False
            hdrs_end = 4 + count * PART_HEADER_SIZE
            if hdrs_end + PART_HEADER_SIZE > size:
                return False
            f.seek(4 + (count - 1) * PART_HEADER_SIZE)
            raw = f.read(PART_HEADER_SIZE)
            lo_off, lo_size, hi_off, hi_size, _name = struct.unpack(PART_HEADER_FMT, raw)
            last_end = hdrs_end + hi_off * 0x100000000 + lo_off + hi_size * 0x100000000 + lo_size
            return last_end == size
    except OSError:
        return False


def read_partitions(path):
    """Read the partition table of an .nb0.

    Args:
        path: The path of the .nb0 firmware.

    Returns:
        tuple: (number of partitions, offset of the data area, the partitions)."""
    with open(path, "rb") as f:
        head = f.read(4)
        count = struct.unpack("<I", head)[0]
        hdrs_end = 4 + count * PART_HEADER_SIZE
        parts = []
        f.seek(4)
        for _ in range(count):
            raw = f.read(PART_HEADER_SIZE)
            lo_off, lo_size, hi_off, hi_size, name_raw = struct.unpack(PART_HEADER_FMT, raw)
            parts.append({
                "name": _cstr(name_raw),
                "data_offset": hdrs_end + hi_off * 0x100000000 + lo_off,
                "file_size": hi_size * 0x100000000 + lo_size,
            })
    return count, hdrs_end, parts


def unpack_nb0(src, out_dir):
    """Extract the partitions of an .nb0 into a directory.

    Args:
        src: The path of the .nb0 firmware.
        out_dir: The output directory.

    Raises:
        ValueError: When the size of the file does not match the partition
            table.
        OSError: When the data of the firmware is truncated while it is read."""
    count, hdrs_end, parts = read_partitions(src)
    filesize = os.path.getsize(src)
    last = parts[-1]
    expected = last["data_offset"] + last["file_size"]
    if filesize != expected:
        raise ValueError("The file size does not match: got {}, expected {} (this is not an .nb0 firmware)".format(filesize, expected))
    os.makedirs(out_dir, exist_ok=True)
    echo("> Partitions: {}  data area offset: {}".format(count, hdrs_end))
    seen = {}
    jobs = []
    for part in parts:
        name = part["name"]
        data_offset = part["data_offset"]
        file_size = part["file_size"]
        if file_size == 0:
            continue
        dst = os.path.join(out_dir, name)
        if os.path.isfile(dst):
            if os.path.getsize(dst) == file_size:
                echo("> Skipped the duplicate entry: {}".format(name))
                continue
            seen[name] = seen.get(name, 0) + 1
            dst = os.path.join(out_dir, "{}_{}.img".format(name, seen[name]))
        echo("> Extracted {} ({} bytes)".format(name, file_size))
        jobs.append((name, data_offset, file_size, dst))

    def work(job):
        """Extract a single partition.

    Args:
        job: (name, data offset, length, output path)."""
        name, data_offset, file_size, dst = job
        with open(src, "rb") as f, open(dst, "wb") as wf:
            f.seek(data_offset)
            remain = file_size
            while remain > 0:
                piece = f.read(min(CHUNK, remain))
                if not piece:
                    raise OSError("The nb0 data is truncated: {}".format(name))
                wf.write(piece)
                remain -= len(piece)

    threads = _extract_threads()
    if threads > 1 and len(jobs) > 1 and ThreadPoolExecutor is not None:
        with ThreadPoolExecutor(max_workers=min(threads, len(jobs))) as pool:
            list(pool.map(work, jobs))
    else:
        for job in jobs:
            work(job)




def run_nb0unpack(args):
    """Run the listing of the partitions or the unpack.

    Args:
        args: The parsed arguments with the file, out, list and auto fields."""
    src = resolve_input(getattr(args, "file", ""))
    if not src or not os.path.isfile(src):
        echo("> Not found: {}".format(src or "<empty>"))
        return
    out = (getattr(args, "out", "") or "").strip()
    if not out:
        base = os.path.splitext(os.path.basename(src))[0]
        out = os.path.join(_pro_dir() or os.path.dirname(src), base + "_nb0")
    out = os.path.abspath(out)
    if getattr(args, "list", False):
        try:
            count, hdrs_end, parts = read_partitions(src)
            filesize = os.path.getsize(src)
            last = parts[-1]
            if filesize != last["data_offset"] + last["file_size"]:
                echo("> Warning: this is not a valid .nb0 firmware (the size does not match)")
            echo("> Data area offset: {}".format(hdrs_end))
            listing.print_partitions(
                [
                    {
                        "name": part["name"],
                        "size": part["file_size"],
                        "offset": part["data_offset"],
                    }
                    for part in parts
                ],
                title="Partitions",
                stream=sys.stdout,
            )
            return
        except Exception as exc:
            debug_exc("nb0unpack list: ")
            echo("> Reading failed: {}".format(exc))
            return
    try:
        echo("> Start the extraction: {} <nb0>".format(os.path.basename(src)))
        if os.path.isdir(out):
            shutil.rmtree(out)
        unpack_nb0(src, out)
        echo("> Extraction complete, files are in: {}".format(out))
    except Exception as exc:
        debug_exc("nb0unpack failed: ")
        echo("> Extracting the nb0 firmware failed: {}".format(exc))
        return


def parse_argv(argv):
    """Parse the nb0unpack command line arguments.

    Args:
        argv: The argument list without the program name.

    Returns:
        Namespace: The parsed arguments."""
    p = argparse.ArgumentParser(prog="nb0unpack", description="Unpack FIH firmware (.nb0, Nokia etc)")
    p.add_argument("file", help="Path to .nb0 firmware file")
    p.add_argument("out", nargs="?", default="", help="Output directory")
    p.add_argument("--list", action="store_true", help="List partitions only, no extract")
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
    run_nb0unpack(args)


if __name__ == "__main__":
    main()
