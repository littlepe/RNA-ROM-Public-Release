# -*- coding: utf-8 -*-
"""Output and debug logging.

Normal log lines go to stdout and are flushed right away, which keeps them
usable in a pipeline; errors and debug output go to stderr.
"""

from __future__ import print_function

import os
import sys
import traceback

_enabled = None


def set_debug(on):
    """Turn the debug output on or off.

    Args:
        on: Enable the debug output when true.

    Returns:
        bool: The new state.
    """
    global _enabled
    _enabled = bool(on)
    os.environ["OEM_DEBUG"] = "1" if on else "0"
    return _enabled


def enabled():
    """Check whether the debug output is enabled.

    Returns:
        bool: True when it is enabled.
    """
    if _enabled is not None:
        return _enabled
    value = os.getenv("OEM_DEBUG") or os.getenv("RNA_DEBUG") or ""
    return value.strip().lower() in ("1", "true", "yes", "on")


def debug(msg):
    """Write one log line to stderr while the debug output is enabled.

    Args:
        msg: The log text.
    """
    if not enabled():
        return
    try:
        sys.stderr.write("> [DBG] {}\n".format(msg))
        sys.stderr.flush()
    except Exception:
        pass


def debug_exc(prefix="exception: "):
    """Print the current traceback while the debug output is enabled.

    Args:
        prefix: A prefix for the line.
    """
    if not enabled():
        return
    debug(prefix + traceback.format_exc().replace("\n", " | "))


def file_info(path):
    """Summarise a file: whether it exists, its size and its type.

    Args:
        path: The file path.

    Returns:
        str: The summary.
    """
    if not path:
        return "<empty>"
    if os.path.isfile(path):
        size = os.path.getsize(path)
        kind = "?"
        try:
            from .gettype import gettype

            kind = gettype(path)
        except Exception as exc:
            kind = "err:{}".format(exc)
        return "{} exists=1 size={} type={}".format(path, size, kind)
    if os.path.isdir(path):
        return "{} exists=1 (dir)".format(path)
    return "{} exists=0".format(path)


def apply_args(args):
    """Apply the debug switches of a parsed namespace.

    Args:
        args: The parsed arguments.
    """
    if getattr(args, "quiet", False):
        set_debug(False)
    elif getattr(args, "debug", False):
        set_debug(True)


def out(msg=""):
    """Write one line to stdout and flush it.

    Args:
        msg: The text to write.
    """
    try:
        sys.stdout.write(str(msg) + "\n")
        sys.stdout.flush()
    except Exception:
        pass


def warn(msg):
    """Print a warning line.

    Args:
        msg: The warning text.
    """
    out("! " + str(msg))


def err(msg):
    """Print an error line to stderr.

    Args:
        msg: The error text.
    """
    try:
        sys.stderr.write(str(msg) + "\n")
        sys.stderr.flush()
    except Exception:
        pass


def setup_output():
    """Switch the standard output to UTF-8.

    A Windows console uses a local code page such as GBK by default, which
    breaks on non ASCII output; everything is written as UTF-8 and characters
    that cannot be encoded are replaced.

    Returns:
        bool: True when the streams were reconfigured.
    """
    changed = False
    for stream in (sys.stdout, sys.stderr):
        encoding = (getattr(stream, "encoding", "") or "").lower().replace("-", "")
        if encoding in ("utf8",):
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
            changed = True
        except Exception:
            pass
    return changed


__all__ = [
    "out", "warn", "err", "debug", "debug_exc", "file_info",
    "apply_args", "set_debug", "enabled", "setup_output",
]
