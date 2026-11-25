#!/usr/bin/env python3
"""OPEX analysis: reads opex.cfg straight from the remote ZIP, the whole
archive never has to be downloaded.
Author: Jerry Tse
"""

# SPDX-License-Identifier: LGPL-3.0-or-later
# Derived from OPlus-Tracker (https://github.com/JerryTse-OSS/OPlus-Tracker)
# Copyright (C) Jerry Tse
# Licensed under the GNU Lesser General Public License v3.0 or later,
# see src/getrom/licenses/OPlus-Tracker/LICENSE for the full text.
import argparse
import json
import sys
from remotezip import RemoteZip

from ...log import out, err

def analyze_opex_from_url(url: str):
    """Extract opex.cfg from the remote ZIP and analyse it."""
    try:
        with RemoteZip(url) as rz:
            # List the files of the ZIP to find opex.cfg
            file_list = rz.namelist()
            cfg_path = None
            for name in file_list:
                if name.endswith('opex.cfg'):   # supports root or subdirectory
                    cfg_path = name
                    break

            if not cfg_path:
                err('Error: opex.cfg not found in the ZIP file')
                sys.exit(1)

            # Read that file only
            with rz.open(cfg_path) as f:
                cfg_data = f.read().decode('utf-8')

            # Parse the JSON
            try:
                cfg = json.loads(cfg_data)
            except json.JSONDecodeError as e:
                err(f"Error: opex.cfg is not valid JSON\n{e}")
                sys.exit(1)

            # Pull out the businessCode
            business_code = cfg.get('businessCode', '')

            # Pull the ovlMountPath out of ovlList
            ovl_list = cfg.get('ovlList', [])
            ovl_paths = [item.get('ovlMountPath', '') for item in ovl_list if item.get('ovlMountPath')]

            if not business_code and not ovl_paths:
                out('Warning: businessCode or ovlMountPath fields not found')

            # Format the output, the same way the original Bash script did
            if business_code and ovl_paths:
                if len(ovl_paths) == 1:
                    path_str = f'"{ovl_paths[0]}"'
                else:
                    # Join with commas, the last item with and
                    quoted = [f'"{p}"' for p in ovl_paths]
                    path_str = ', '.join(quoted[:-1]) + f' and {quoted[-1]}'
                out(f'\n"{business_code}" is used to fix {path_str}')
            else:
                out('Cannot generate a complete analysis result')

            # Show the details
            out('Details:')
            out(f"OPEX code: {business_code}")
            out(f"ovlList count: {len(ovl_paths)}")
            if ovl_paths:
                out('ovlMountPath list:')
                for p in ovl_paths:
                    out(f"  - {p}")

    except Exception as e:
        err(f"Error: {e}")
        # A common failure: the server does not support Range requests
        if '416' in str(e) or 'range' in str(e).lower():
            err('Hint: The remote server may not support Range requests; partial download is unavailable.')
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description='OPEX analysis tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='\nExample:\n  python3 %(prog)s <URL>\n'
    )
    parser.add_argument('url', help='link to resolve')
    args = parser.parse_args()

    url = args.url
    
    if not url:
        err('Error: link cannot be empty')
        sys.exit(1)

    analyze_opex_from_url(url)
    out('> Analysis complete')

if __name__ == '__main__':
    main()