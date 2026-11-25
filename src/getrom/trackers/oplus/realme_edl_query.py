#!/usr/bin/env python
"""Query the official Realme EDL packages
Author: Jerry Tse
"""

# SPDX-License-Identifier: LGPL-3.0-or-later
# Derived from OPlus-Tracker (https://github.com/JerryTse-OSS/OPlus-Tracker)
# Copyright (C) Jerry Tse
# Licensed under the GNU Lesser General Public License v3.0 or later,
# see src/getrom/licenses/OPlus-Tracker/LICENSE for the full text.
import argparse
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


from ...log import out

def check_url(url):
    try:
        resp = requests.head(url, timeout=2, allow_redirects=True)
        if resp.status_code == 200:
            return url
    except Exception:
        return None
    return None


def query_realme_edl(version_name: str, region: str, date_prefix: str):
    if len(date_prefix) != 12:
        raise ValueError(f"The date length is {len(date_prefix)}, it must be 12 characters.")

    from .config import REALME_CONFIG

    region = region.upper()
    if region in ("EU", "EUEX", "EEA", "TR"):
        conf = REALME_CONFIG["gdpr"]
    elif region in ("CN", "CH"):
        conf = REALME_CONFIG["domestic"]
    else:
        conf = REALME_CONFIG["export"]

    BUCKET, SERVER = conf["bucket"], conf["server"]

    VERSION_CLEAN = (
        re.sub(r"^RMX\d+_", "", version_name).replace("(", "").replace(")", "")
    )
    MODEL = version_name.split("_")[0]
    BASE_URL = f"https://{SERVER}/sw/{MODEL}{BUCKET}_11_{VERSION_CLEAN}_{date_prefix}"

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [
            executor.submit(check_url, f"{BASE_URL}{i:04d}.zip") for i in range(10000)
        ]
        for future in as_completed(futures):
            result = future.result()
            if result:
                for pending in futures:
                    pending.cancel()
                return result
    return None


def main():
    parser = argparse.ArgumentParser(
        description='Realme EDL query tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='\nExample:\n  python %(prog)s "RMX3888_16.0.3.500(CN01)" CN 202601241320\n',
    )
    parser.add_argument(
        "version_name",
        metavar="VERSION_NAME",
        help='version name (e.g. RMX3888_16.0.3.500(CN01))',
    )
    parser.add_argument(
        "region", metavar="REGION", help='region code (e.g. CN, EU, IN)'
    )
    parser.add_argument(
        "date", metavar="DATE", help='12-digit date prefix (e.g. 202601241320)'
    )
    args = parser.parse_args()

    out(f"> Query: {args.version_name}\n")
    found = query_realme_edl(args.version_name, args.region, args.date)
    out('> Result:')
    if found:
        out(f"  Link: {found}")
        return 0
    out('  Link: not found')
    return 1


if __name__ == "__main__":
    sys.exit(main())
