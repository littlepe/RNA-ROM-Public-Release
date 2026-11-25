#!/usr/bin/env python
# SPDX-License-Identifier: LGPL-3.0-or-later
# Derived from OPlus-Tracker (https://github.com/JerryTse-OSS/OPlus-Tracker)
# Copyright (C) Jerry Tse
# Licensed under the GNU Lesser General Public License v3.0 or later,
# see src/getrom/licenses/OPlus-Tracker/LICENSE for the full text.
import argparse
import random
import re
import string
import sys
from typing import Dict, Tuple

import requests

from .config import IOT_NEW_CONFIG

SPECIAL_SERVERS = IOT_NEW_CONFIG["special_servers"]


from ...log import out

def replace_gauss_url(url: str) -> str:
    if not url or url == 'Unknown':
        return url
    return url.replace(IOT_NEW_CONFIG["gauss_auto_url"], IOT_NEW_CONFIG["gauss_manual_url"])


def build_special_request_data(ota_version: str, hardware_version: str, region: str) -> Tuple[Dict, Dict]:
    lang = "zh-CN" if region.lower() == "cn" else "en-EN"
    
    mobile = ota_version.split("_")[0]
    random_imei = "".join(random.choices(string.digits, k=15))

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


    body = {
        "version": "1",
        "mobile": mobile,
        "ota_version": ota_version,
        "imei": random_imei,
        "mode": 0,                                
        "hardwareVersion": hardware_version,               # ro.product.name Required
        "language": lang,
        "beta": "0",
        "type": "0",
        "isRooted": "0",
        "new_rooted_check": "0",
        "operator": "0",                        # Fill in anything
    }

    return headers, body


def query_iot_server(ota_version: str, hardware_version: str, region: str):
    headers, body = build_special_request_data(ota_version, hardware_version, region)
    
    server_url = SPECIAL_SERVERS.get(region.lower(), SPECIAL_SERVERS["cn"]) + "Query_Update"

    try:
        response = requests.post(
            server_url,
            headers=headers,
            json=body,
            timeout=30,
        )
        if response.status_code != 200:
            return None

        resp_json = response.json()

        return resp_json
    except Exception:
        return None


def build_iot_result(resp_json):
    module_data = resp_json.get("modules", [{}])[0]
    data = {**resp_json, **module_data}
    
    down_url = replace_gauss_url(data.get("down_url", 'Unknown'))
    file_name = str(data.get("patch_name", 'Unknown'))
    changelog = replace_gauss_url(str(data.get("description", 'Unknown')))
    patch_level = str(data.get("googlePatchLevel", 'Unknown')).replace("0", 'Unknown')
    return {
        "link": down_url,
        "file_name": file_name,
        "changelog": changelog,
        "security_patch": patch_level,
        "version": data.get("new_version", 'Unknown'),
        "ota_version": data.get("version_name", data.get("new_version", 'Unknown')),
    }


def query_iot(ota_prefix: str, region: str, hardware_version: str):
    ota_input = ota_prefix.upper()

    is_simple = not bool(
        re.search(r"_\d{2}\.[A-Z]", ota_input) or ota_input.count("_") >= 3
    )
    results = []

    if is_simple:
        suffixes = ["_11.A", "_11.C", "_11.F", "_11.H"]

        for suffix in suffixes:
            current_prefix = ota_input + suffix
            full_version = f"{current_prefix}.01_0001_197001010000"
            
            result = query_iot_server(full_version, hardware_version, region)
            
            if result:
                results.append(
                    {
                        "query": current_prefix,
                        "found": True,
                        "result": build_iot_result(result),
                    }
                )
            else:
                results.append(
                    {"query": current_prefix, "found": False, "result": None}
                )

    else:
        parts = ota_input.split("_")
        full_version = (
            f"{ota_input}.01_0001_197001010000" if len(parts) < 3 else ota_input
        )
        
        result = query_iot_server(full_version, hardware_version, region)
        
        if result:
            results.append(
                {"query": ota_input, "found": True, "result": build_iot_result(result)}
            )
        else:
            results.append({"query": ota_input, "found": False, "result": None})
    return results


def main():
    parser = argparse.ArgumentParser(description='IOT dedicated OTA query tool')
    parser.add_argument("ota_prefix", help='OTA version prefix')
    parser.add_argument("hardware_version", help='hardware version (ro.product.name)')
    parser.add_argument(
        "region", choices=["cn", "foreign"], help='query region (cn, foreign)'
    )

    args = parser.parse_args()
    
    results = query_iot(args.ota_prefix, args.region, args.hardware_version)
    
    has_result = False
    for item in results:
        out(f"> Query: {item['query']}\n")
        if not item["found"]:
            out('> No results\n')
            continue
        has_result = True
        data = item["result"]
        out('> Result:')
        out(f"  Link: {data['link']}")
        out(f"  File name: {data['file_name']}")
        out(f"  Changelog: {data['changelog']}")
        out(f"  Security patch: {data['security_patch']}")
        out(f"  Version: {data['version']}")
        out(f"  OTA version: {data['ota_version']}\n")
    return 0 if has_result else 1


if __name__ == "__main__":
    sys.exit(main())
