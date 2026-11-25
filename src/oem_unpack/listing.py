# -*- coding: utf-8 -*-
"""One format for the partition lists of every vendor.

The unpackers of the different vendors find their partitions in very
different ways, but the list they print is the same thing every time. This
module holds the format, so that the output of ``--list`` looks the same
wherever it comes from:

.. code-block:: text

    > Partitions (3):
      #   Name                    Size         Offset
      1   system             123.4 MiB     0x00001000
      2   super                1.2 GiB     0x02002000
      3   userdata             8.0 GiB     0x10003000
"""

from __future__ import print_function

import sys

#: The columns of the table.
COLUMNS = ("#", "Name", "Size", "Offset")

#: The width of the name column when it is not wider than that.
NAME_WIDTH = 24


def human_size(size):
    """Format a byte count with a unit.

    Args:
        size: The number of bytes.

    Returns:
        str: The text, for instance 1.5 MiB.
    """
    try:
        value = float(size)
    except (TypeError, ValueError):
        return str(size or "")
    if value < 1024:
        return "{} B".format(int(value))
    for unit in ("KiB", "MiB", "GiB", "TiB"):
        value /= 1024.0
        if value < 1024 or unit == "TiB":
            return "{:.1f} {}".format(value, unit)
    return "{:.1f} TiB".format(value)


def format_offset(offset):
    """Format an offset as a hex number.

    Args:
        offset: The offset in bytes, None when it is not known.

    Returns:
        str: The text, for instance 0x00001000.
    """
    if offset is None:
        return ""
    try:
        return "0x{:08X}".format(int(offset))
    except (TypeError, ValueError):
        return str(offset)


def partition_rows(rows):
    """Normalise the partition rows of the different vendors.

    Every row is a mapping with the keys name, size and offset, the size and
    the offset are optional. A row may also carry a type and a note, they show
    up as extra columns.

    Args:
        rows: The rows.

    Returns:
        list: The normalised rows.
    """
    out = []
    for row in rows or []:
        if isinstance(row, dict):
            name = row.get("name") or ""
            size = row.get("size")
            offset = row.get("offset")
            kind = row.get("type") or row.get("file_type") or ""
            note = row.get("note") or ""
        else:
            name = row[0] if len(row) > 0 else ""
            size = row[1] if len(row) > 1 else None
            offset = row[2] if len(row) > 2 else None
            kind = ""
            note = ""
        out.append({
            "name": str(name),
            "size": size,
            "offset": offset,
            "type": str(kind),
            "note": str(note),
        })
    return out


def print_partitions(rows, title="Partitions", stream=None):
    """Print the partitions in the shared table.

    Args:
        rows: The partitions, every row is a mapping with the keys name, size
            and offset; the size and the offset are optional and a row may
            carry a type and a note.
        title: The title of the table.
        stream: Where to write, stdout by default.
    """
    out = stream if stream is not None else sys.stdout
    items = partition_rows(rows)
    if not items:
        out.write("> {}: none\n".format(title))
        return
    has_type = any(item["type"] for item in items)
    has_note = any(item["note"] for item in items)
    width = max([len(COLUMNS[1])] + [len(item["name"]) for item in items])
    width = min(max(width, NAME_WIDTH), 40)
    header = "  {:>3}  {:<{w}}  {:>12}  {:>10}".format(
        COLUMNS[0], COLUMNS[1], COLUMNS[2], COLUMNS[3], w=width)
    if has_type:
        header += "  {:<10}".format("Type")
    if has_note:
        header += "  {}".format("Note")
    out.write("> {} ({}):\n".format(title, len(items)))
    out.write(header + "\n")
    for index, item in enumerate(items, 1):
        size = human_size(item["size"]) if item["size"] is not None else ""
        name = item["name"]
        if len(name) > width:
            name = name[:width - 3] + "..."
        line = "  {:>3}  {:<{w}}  {:>12}  {:>10}".format(
            index, name, size, format_offset(item["offset"]), w=width)
        if has_type:
            line += "  {:<10}".format(item["type"])
        if has_note:
            line += "  {}".format(item["note"])
        out.write(line + "\n")
