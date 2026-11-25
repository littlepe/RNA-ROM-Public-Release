# -*- coding: utf-8 -*-
"""getrom command line entry.

Query only: there is no device database (no local files, no cloud downloads),
so every device attribute comes from the command line.

.. code-block:: bash

    getrom xiaomi --device fuxi --version OS1.0.6.0.VOZCNXM --android 15.0 --region CN
    getrom vivo --device PD2301:V2301A --version V14.0.1.0.TVACNXM --android 14
    getrom stepaos --device PZ261A --version "Step AOS 1.0.0.2.26001_stable_user_20261004_131555"
"""

from __future__ import print_function

import argparse
import sys

from . import config
from .log import out, set_debug, setup_output
from .vendors import coloros, lenovo, obric, stepaos, vivo, xiaomi

#: Vendor aliases mapped to their module.
VENDORS = {
    "vivo": vivo,
    "iqoo": vivo,
    "xiaomi": xiaomi,
    "mi": xiaomi,
    "redmi": xiaomi,
    "poco": xiaomi,
    "obric": obric,
    "ocean": obric,
    "ocean2": obric,
    "pacific": obric,
    "lenovo": lenovo,
    "lenovopad": lenovo,
    "xiaoxin": lenovo,
    "legion": lenovo,
    "coloros": coloros,
    "oppo": coloros,
    "oneplus": coloros,
    "realme": coloros,
    "oplus": coloros,
    "stepaos": stepaos,
    "stepx": stepaos,
    "mzupdate": stepaos,
}

#: Vendor list shown by ``getrom --list``.
VENDOR_LIST = (
    ("vivo", "Vivo / iQOO"),
    ("xiaomi", "Xiaomi / Redmi / POCO"),
    ("obric", "Obric / Pacific / Ocean2"),
    ("lenovo", "Lenovo Xiaoxin / Legion tablets"),
    ("oplus", "OPPO / OnePlus / Realme (ColorOS)"),
    ("stepaos", "StepAOS / StepX"),
)

#: Tracker vendor aliases.
TRACKER_VENDORS = ("tracker", "trackers", "oplus-tracker", "oplus2", "vivo-tracker", "vivo2")

#: Xiaomi account sub commands.
XIAOMI_AUTH_VENDORS = ("xiaomi-login", "xiaomi-auth-status", "xiaomi-auth-clear")

USAGE = "> Usage: getrom vivo|xiaomi|obric|lenovo|oplus|stepaos [--device ...] [--version ...]"


def build_parser():
    """Build the command line parser.

    Returns:
        ArgumentParser: The parser.
    """
    parser = argparse.ArgumentParser(
        prog="getrom",
        description="Query official OTA firmware (vivo / Xiaomi / Obric / Lenovo / ColorOS / StepAOS)",
    )
    parser.add_argument("vendor", nargs="?", default="", help="vendor or sub command")
    parser.add_argument("--list", action="store_true", help="kept for compatibility, prints nothing")
    parser.add_argument("--device", default="", help="device codename or 'codename:software model'")
    parser.add_argument("--codename", default="", help="device codename")
    parser.add_argument("--model", default="", help="device name or software model")
    parser.add_argument("--sw", default="", help="software model")
    parser.add_argument("--version", default="", help="current firmware version")
    parser.add_argument("--android", default="", help="Android version, e.g. 15.0 / 16")
    parser.add_argument("--region", default="CN", help="region, e.g. CN / GL / EU")
    parser.add_argument("--user", default="", help="account name")
    parser.add_argument("--password", default="", help="password (or use XIAOMI_PASSWORD)")
    parser.add_argument("--type", dest="acc_type", default="", help="account region: CN / GL")
    parser.add_argument("--system", default="", help="system version filter, e.g. 10 / 6.1")
    parser.add_argument("--branch", default="", help="update branch: A / C / F / H / J")
    parser.add_argument("--full", default="1", help="full package flag: 1 / 0")
    parser.add_argument("--channel", default="NORMAL", help="channel: NORMAL / TRIAL / BETA / ALPHA")
    parser.add_argument("--dtype", default="", help="device type: phone / tablet")
    parser.add_argument("--sn", default="A0000000000000A", help="serial number")
    parser.add_argument("--rom-version", dest="rom_version", default="", help="current ROM version")
    parser.add_argument("--build-time", dest="build_time", default="", help="build timestamp")
    parser.add_argument("--build-type", dest="build_type", default="", help="build type: user / userdebug")
    parser.add_argument("--udid", default="", help="device unique id")
    parser.add_argument("--language", default="zh", help="language, e.g. zh / en")
    parser.add_argument("--flag", default="1", help="OTA flag")
    parser.add_argument("--max-hops", dest="max_hops", default="10", help="max OTA chain hops")
    parser.add_argument("--target-version", dest="target_version", default="", help="target version")
    parser.add_argument("--download", default="", help="download directory; 1 means the default one")
    parser.add_argument("--verify", default="1", help="verify MD5 after download")
    parser.add_argument("--debug", action="store_true", help="print debug logs")
    parser.add_argument("--quiet", action="store_true", help="disable debug logs")
    parser.add_argument("--tool", nargs="?", const="", default="", help="tracker tool name")
    parser.add_argument("--args", nargs="?", const="", default="", help="raw tracker arguments")
    parser.add_argument("--mode", nargs="?", const="", default="", help="tracker mode")
    parser.add_argument("--guid", nargs="?", const="", default="", help="tracker GUID")
    parser.add_argument("--components", nargs="?", const="", default="", help="tracker components")
    parser.add_argument("--anti", nargs="?", const="", default="", help="tracker anti flag")
    parser.add_argument("--genshin", nargs="?", const="", default="", help="tracker genshin flag")
    parser.add_argument("--pre", nargs="?", const="", default="", help="tracker pre flag")
    parser.add_argument("--nvid", nargs="?", const="", default="", help="tracker nvid")
    parser.add_argument("--recruit", nargs="?", const="", default="", help="tracker recruit flag")
    parser.add_argument("--original-link", dest="original_link", nargs="?", const="", default="",
                        help="tracker original link flag")
    parser.add_argument("--pki", nargs="?", const="", default="", help="tracker PKI flag")
    parser.add_argument("--info", nargs="?", const="", default="", help="tracker extra info")
    parser.add_argument("--brand", nargs="?", const="", default="", help="tracker brand")
    parser.add_argument("--coloros", nargs="?", const="", default="", help="tracker ColorOS version")
    parser.add_argument("--prj", nargs="?", const="", default="", help="tracker prj")
    parser.add_argument("--duid", nargs="?", const="", default="", help="tracker duid")
    parser.add_argument("--date", nargs="?", const="", default="", help="tracker date")
    parser.add_argument("--hardware", nargs="?", const="", default="", help="tracker hardware code")
    parser.add_argument("--url", nargs="?", const="", default="", help="tracker URL")
    parser.add_argument("--prodid", nargs="?", const="", default="", help="tracker product id")
    parser.add_argument("--cmcc", nargs="?", const="", default="", help="tracker cmcc flag")
    return parser


def _print_vendor_list():
    """Print the supported vendors."""
    for name, desc in VENDOR_LIST:
        out("{}|{}".format(name, desc))


def _run_tracker(vendor, args, listing):
    """Dispatch to the VIVO / OPlus tracker bridge.

    Args:
        vendor: The vendor alias.
        args: The parsed arguments.
        listing: Whether the tool list was requested.

    Returns:
        int: The exit code.
    """
    from .trackers import list_tools, run_tracker

    tool = (getattr(args, "tool", "") or "").strip().lower()
    if not tool:
        if vendor.startswith("vivo"):
            tool = "vivo"
        elif vendor.startswith("oplus"):
            tool = "tomboy"
    if listing or not tool:
        for name in list_tools():
            out(name)
        return 0
    return run_tracker(tool, args)


def _print_paths():
    """Print the directories and platform in use."""
    out("> Platform: {}".format(config.platform_name()))
    out("> Config directory: {}".format(config.config_dir()))
    out("> Data directory: {}".format(config.data_dir()))


def run(args):
    """Dispatch a query to the matching vendor module.

    Args:
        args: The parsed arguments.

    Returns:
        int: The exit code, 0 on success.
    """
    vendor = (getattr(args, "vendor", "") or "").strip().lower()
    listing = bool(getattr(args, "list", False))
    if vendor in ("", "all"):
        if listing:
            _print_vendor_list()
            return 0
        _print_paths()
        out(USAGE)
        out(">        getrom tracker --tool <name>")
        return 0
    if vendor in ("info", "paths", "config"):
        _print_paths()
        return 0
    if vendor in XIAOMI_AUTH_VENDORS:
        xiaomi.run_auth(vendor, args)
        return 0
    if vendor in TRACKER_VENDORS:
        return _run_tracker(vendor, args, listing)
    module = VENDORS.get(vendor)
    if module is None:
        out(USAGE)
        out(">        getrom tracker --tool <name>")
        return 2
    if listing:
        # The device database is gone; --list is kept for compatibility only.
        return 0
    if vendor in ("obric", "ocean", "ocean2", "pacific"):
        if not (getattr(args, "device", None) or "").strip():
            if vendor.startswith("ocean"):
                args.device = "Ocean2"
            elif vendor == "pacific":
                args.device = "Pacific"
    module.query(args)
    return 0


def run_getrom(args):
    """Entry point for the RNA-ROM main program.

    The main program hands over its own argparse namespace, so the arguments
    are read with getattr and every one of them may be missing.

    Args:
        args: The parsed arguments.

    Returns:
        int: The exit code, 0 on success.
    """
    return run(args)


def main(argv=None):
    """The command line entry point.

    Args:
        argv: The argument list, sys.argv[1:] by default.

    Returns:
        int: The exit code, 0 on success.
    """
    argv = list(sys.argv[1:] if argv is None else argv)
    while argv and argv[0] in ("getrom", "rna", "dna"):
        argv = argv[1:]
    setup_output()
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "quiet", False):
        set_debug(False)
    elif getattr(args, "debug", False):
        set_debug(True)
    try:
        return run(args)
    except KeyboardInterrupt:
        out("> Interrupted by user")
        return 130
    except Exception as exc:
        out("> Request failed: {}".format(exc))
        if getattr(args, "debug", False):
            from .log import debug_exc

            debug_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
