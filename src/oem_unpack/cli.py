# -*- coding: utf-8 -*-
"""Command line entry of the vendor unpackers.

Every vendor format gets its own sub command:

.. code-block:: bash

    oem-unpack huawei  UPDATE.APP            # Huawei APP / update.bin
    oem-unpack kdz     firmware.kdz         # LG KDZ / DZ
    oem-unpack pac     firmware.pac         # Unisoc PAC
    oem-unpack sony    firmware.sin         # Sony SIN
    oem-unpack oppo    firmware.ozip        # OPPO / Realme / OnePlus ozip, ofp, ops
    oem-unpack ampack  firmware.img         # AMLogic
    oem-unpack rkfw    firmware.rkfw        # Rockchip RKFW / RKAF
    oem-unpack nb0     firmware.nb0         # Nokia NB0

The unpack only produces the partition images, the images themselves are not
opened any further: that is what needs the external binaries.
"""

from __future__ import print_function

import argparse
import os
import sys

from .log import err, out, setup_output

#: The sub commands with their description.
COMMANDS = (
    ("huawei", "Huawei UPDATE.APP / update.bin"),
    ("kdz", "LG KDZ / DZ"),
    ("pac", "Unisoc PAC"),
    ("sony", "Sony SIN"),
    ("oppo", "OPPO / Realme / OnePlus ozip, ofp, ops"),
    ("ampack", "AMLogic image"),
    ("rkfw", "Rockchip RKFW / RKAF"),
    ("nb0", "Nokia NB0"),
)


def _huawei(args):
    """Unpack a Huawei firmware.

    Args:
        args: The parsed arguments.

    Returns:
        int: The exit code.
    """
    from . import huawei_firmware_extractor as engine

    argv = [args.file]
    if args.out:
        argv += ["--output-dir", args.out]
    if args.list:
        argv.append("--list")
    if args.partition:
        argv += ["--partition", args.partition]
    return engine.main(argv)


def _kdz(args):
    """Unpack an LG KDZ or DZ.

    Args:
        args: The parsed arguments.

    Returns:
        int: The exit code.
    """
    from . import kdzextract as engine

    if args.list:
        engine.print_slices(engine.list_slices(args.file))
        return 0
    wanted = set(args.partition.split(",")) if args.partition else None
    engine.extract_slices(
        args.file,
        args.out,
        wanted=wanted,
        params=args.params,
        rawprogram=args.rawprogram,
        dz_params=args.dz_params,
        images=1,
    )
    return 0


def _pac(args):
    """Unpack a Unisoc PAC.

    Args:
        args: The parsed arguments.

    Returns:
        int: The exit code.
    """
    from . import pac_extract as engine

    out_dir = args.out or os.path.join(os.path.dirname(args.file) or ".", "ImageFiles")
    extractor = engine.PacExtractor(args.file, out_dir, not args.no_crc, args.debug)
    extractor.extract()
    return 0


def _sony(args):
    """Unpack a Sony SIN.

    Args:
        args: The parsed arguments.

    Returns:
        int: The exit code.
    """
    from . import sony_dump as engine

    argv = [args.file]
    if args.out:
        argv.append(args.out)
    return engine.main(argv)


def _oppo(args):
    """Decrypt the firmware of OPPO, Realme or OnePlus.

    Args:
        args: The parsed arguments.

    Returns:
        int: The exit code.
    """
    from . import oppo_decrypt as engine

    argv = [args.file]
    if args.out:
        argv += ["--out", args.out]
    if args.rec:
        argv += ["--rec", args.rec]
    if args.custom_key:
        argv += ["--custom_key", args.custom_key]
    return engine.main(argv)


def _ampack(args):
    """Unpack an AMLogic image.

    Args:
        args: The parsed arguments.

    Returns:
        int: The exit code.
    """
    from . import ampack as engine

    argv = [args.action, args.file]
    if args.out:
        argv.append(args.out)
    return engine.main(argv)


def _rkfw(args):
    """Unpack Rockchip RKFW or RKAF firmware.

    Args:
        args: The parsed arguments.

    Returns:
        int: The exit code.
    """
    from . import rkfw as engine

    argv = [args.action, args.file]
    if args.out:
        argv.append(args.out)
    return engine.main(argv)


def _nb0(args):
    """Unpack a Nokia NB0.

    Args:
        args: The parsed arguments.

    Returns:
        int: The exit code.
    """
    from . import nb0unpack as engine

    argv = [args.file]
    if args.out:
        argv.append(args.out)
    if args.list:
        argv.append("--list")
    return engine.main(argv)


#: The handler of every sub command.
HANDLERS = {
    "huawei": _huawei,
    "kdz": _kdz,
    "pac": _pac,
    "sony": _sony,
    "oppo": _oppo,
    "ampack": _ampack,
    "rkfw": _rkfw,
    "nb0": _nb0,
}


def build_parser():
    """Build the command line parser.

    Returns:
        argparse.ArgumentParser: The parser.
    """
    parser = argparse.ArgumentParser(
        prog="oem-unpack",
        description="Unpack the vendor firmware packages (pure Python)",
    )
    sub = parser.add_subparsers(dest="vendor")
    for name, desc in COMMANDS:
        item = sub.add_parser(name, help=desc)
        item.add_argument("file", help="The firmware file")
        item.add_argument("--out", default="", help="The output directory")
        if name in ("huawei", "kdz", "nb0"):
            item.add_argument("--list", action="store_true", help="Only list the partitions")
        if name in ("huawei", "kdz"):
            item.add_argument("--partition", default="", help="The partitions to extract")
        if name == "kdz":
            item.add_argument("--params", action="store_true", help="Write the .img.params")
            item.add_argument("--rawprogram", action="store_true", help="Write the rawprogramN.xml")
            item.add_argument("--dz-params", dest="dz_params", action="store_true",
                              help="Write the .dz.params")
        if name == "pac":
            item.add_argument("--no-crc", dest="no_crc", action="store_true",
                              help="Skip the CRC check")
            item.add_argument("--debug", action="store_true", help="Print the file table")
        if name == "oppo":
            item.add_argument("--rec", default="", help="The recovery image with the keys")
            item.add_argument("--custom-key", dest="custom_key", default="",
                              help="The AES key of the user")
        if name == "ampack":
            item.add_argument("--action", default="unpack",
                              choices=("verify", "unpack", "convert", "pack", "crc32"),
                              help="What to do with the image")
        if name == "rkfw":
            item.add_argument("--action", default="unpack",
                              choices=("unpack", "pack-rkfw", "pack-rkaf"),
                              help="What to do with the firmware")
    return parser


def main(argv=None):
    """The command line entry point.

    Args:
        argv: The argument list, sys.argv by default.

    Returns:
        int: The exit code.
    """
    setup_output()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.vendor:
        parser.print_help()
        return 2
    handler = HANDLERS.get(args.vendor)
    if handler is None:
        err("> Unsupported vendor: {}".format(args.vendor))
        return 2
    try:
        return handler(args) or 0
    except KeyboardInterrupt:
        out("> Interrupted by user")
        return 130
    except Exception as exc:
        err("> Failed: {}".format(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
