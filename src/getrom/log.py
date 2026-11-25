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
    os.environ["GETROM_DEBUG"] = "1" if on else "0"
    return _enabled


def enabled():
    """Check whether the debug output is enabled.

    Returns:
        bool: True when it is enabled.
    """
    if _enabled is not None:
        return _enabled
    value = os.getenv("GETROM_DEBUG") or os.getenv("DNA_DEBUG") or ""
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


def phase(msg):
    """Print a phase message.

    The standalone tool has no host progress channel, so the phase goes to
    stderr to keep stdout clean for the results.

    Args:
        msg: The phase text.
    """
    try:
        sys.stderr.write("... {}\n".format(msg))
        sys.stderr.flush()
    except Exception:
        pass


__all__ = ["out", "warn", "err", "debug", "debug_exc", "set_debug", "enabled", "phase"]
