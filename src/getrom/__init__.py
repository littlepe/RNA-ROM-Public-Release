# -*- coding: utf-8 -*-
"""getrom: a cross platform query tool for official OTA firmware.

Queries the official upgrade endpoints of vivo / iQOO, Xiaomi / Redmi /
POCO, Obric, Lenovo, OPPO / OnePlus / Realme (ColorOS) and StepAOS, and
prints the firmware version, file name and download address.

From the command line::

    getrom --help
    getrom xiaomi --device fuxi --version OS1.0.6.0.VOZCNXM --android 15.0 --region CN
    getrom vivo --device PD2301:V2301A --version V14.0.1.0.TVACNXM --android 14

As a library::

    from getrom.vendors import xiaomi

    xiaomi.query(args)
"""

from __future__ import print_function

__version__ = "1.0.0"

__all__ = ["__version__", "cli", "config", "crypto", "jvq", "log", "net", "vendors"]


def run_getrom(args):
    """Entry point used by the RNA-ROM main program.

    Args:
        args: The parsed arguments of the main program.

    Returns:
        int: The exit code, 0 on success.
    """
    from .cli import run

    return run(args)
