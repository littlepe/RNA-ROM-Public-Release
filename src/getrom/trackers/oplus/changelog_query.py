#!/usr/bin/env python
"""ColorOS changelog query tool
Author: Jerry Tse
"""

# SPDX-License-Identifier: LGPL-3.0-or-later
# Derived from OPlus-Tracker (https://github.com/JerryTse-OSS/OPlus-Tracker)
# Copyright (C) Jerry Tse
# Licensed under the GNU Lesser General Public License v3.0 or later,
# see src/getrom/licenses/OPlus-Tracker/LICENSE for the full text.
import argparse
import json
import re
import sys

import requests

from .config import OTA_REGION_CONFIG

REGION_CONFIG = OTA_REGION_CONFIG

VALID_REGIONS = [r for r in REGION_CONFIG.keys() if r != "sg_host"]
CHINA_REGIONS = ["cn", "cn_cmcc"]  # Use bullet prefix for Chinese regions
DEFAULT_CHANGELOG_SUFFIX = "_197001010000"


from ...log import out

def extract_url_from_link(link_str: str) -> str:
    match = re.search(r'href\s*=\s*"([^"]+)"', link_str)
    return match.group(1) if match else link_str.strip()


def process_version_prefix(orig_prefix: str, pre_flag: int = None):
    """
    Process the version prefix based on pre_flag.
    Returns (model, adjusted_prefix) where:
        - model: pure model name (without PRE) for headers
        - adjusted_prefix: version string to use for full version (may include PRE based on flag)
    pre_flag:
        - None: keep original version string unchanged
        - 0: ensure version string does NOT contain PRE (strip if present)
        - 1: ensure version string contains PRE (add if absent)
    """
    parts = orig_prefix.split("_", 1)
    if len(parts) != 2:
        # The checks above already ruled this out
        model_part = parts[0]
        rest = ""
    else:
        model_part, rest = parts[0], "_" + parts[1]

    # The plain model without PRE, only used for the request headers
    pure_model = model_part.replace("PRE", "")

    if pre_flag is None:
        # Keep the version string as it is
        adjusted_prefix = orig_prefix
    elif pre_flag == 1:
        # Make sure the version string contains PRE
        if "PRE" in model_part:
            adjusted_prefix = orig_prefix  # already has PRE
        else:
            # Add PRE
            new_model_part = model_part + "PRE"
            adjusted_prefix = new_model_part + rest
    else:  # pre_flag == 0
        # Make sure the version string does not contain PRE
        if "PRE" in model_part:
            # Remove PRE
            adjusted_prefix = pure_model + rest
        else:
            adjusted_prefix = orig_prefix  # no PRE, keep as is

    return pure_model, adjusted_prefix


def format_output(data: dict, region: str) -> list:
    upg_inst_detail = data.get("upgInstDetail", [])
    if not upg_inst_detail:
        return ['No update details found.']

    use_bullet = region in CHINA_REGIONS
    first_printed = False
    lines = []

    for item in upg_inst_detail:
        # Regular update categories, with their sub items
        if "children" in item:
            if first_printed:
                lines.append("")
            first_child = True
            for child in item["children"]:
                if not first_child:
                    lines.append("")
                first_child = False
                title = child.get("title", "")
                content_list = child.get("content", [])
                if title:
                    lines.append(title)
                for content_item in content_list:
                    text = (
                        content_item.get("data", "")
                        if isinstance(content_item, dict)
                        else content_item
                    )
                    if text:
                        if use_bullet:
                            lines.append(f"· {text}")
                        else:
                            lines.append(text)
            first_printed = True

        # Link entries, they may carry a text or only a link
        elif "link" in item:
            if first_printed:
                lines.append("")
            content_text = item.get("content", "")
            if content_text:
                lines.append(content_text)
            link_html = item.get("link", "")
            if link_html:
                url = extract_url_from_link(link_html)
                lines.append(url)
            first_printed = True

        # Important notes, in several languages
        elif item.get("type") == "updateTips":
            if first_printed:
                lines.append("")
            title = item.get("title", "Important Notes")
            lines.append(title)
            tips_content = item.get("content", "")
            if tips_content:
                lines.append(tips_content)
            first_printed = True
    return lines


def query_changelog(version_prefix: str, region: str, pre_flag: int = None):
    version_prefix = version_prefix.upper()
    region = region.lower()

    if version_prefix.count("_") != 2:
        raise ValueError(
            f"OTA_Prefix '{version_prefix}' must contain exactly two underscores."
        )
    if region not in VALID_REGIONS:
        available = ", ".join(sorted(VALID_REGIONS))
        raise ValueError(f"Invalid region '{region}'. Available regions: {available}")

    model, adjusted_prefix = process_version_prefix(version_prefix, pre_flag)

    if region in ["cn", "cn_cmcc", "eu", "in"]:
        config = REGION_CONFIG[region]
    else:
        config = REGION_CONFIG["sg_host"].copy()
        config.update(REGION_CONFIG[region])

    full_version = adjusted_prefix + DEFAULT_CHANGELOG_SUFFIX
    url = "https://" + config["host"] + "/descriptionInfo"
    headers = {
        "language": config["language"],
        "nvCarrier": config["carrier_id"],
        "mode": "manual",
        "osVersion": "unknown",
        "maskOtaVersion": full_version,
        "otaVersion": full_version,
        "model": model,
        "androidVersion": "unknown",
        "Content-Type": "application/json",
    }
    inner_params = {
        "mode": 0,
        "maskOtaVersion": full_version,
        "bigVersion": 0,
        "h5LinkVersion": 6,
    }
    payload = {"params": json.dumps(inner_params, ensure_ascii=False)}

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=15)
    except Exception as e:
        return {
            "ok": False,
            "full_version": full_version,
            "error": f"Network error: {e}",
        }

    if response.status_code != 200:
        return {
            "ok": False,
            "full_version": full_version,
            "error": f"HTTP error: {response.status_code}",
        }

    try:
        resp_json = response.json()
    except json.JSONDecodeError:
        return {
            "ok": False,
            "full_version": full_version,
            "error": 'The response is not valid JSON.',
        }

    if resp_json.get("responseCode") == 500 and resp_json.get("errMsg") == "no modify":
        return {
            "ok": True,
            "full_version": full_version,
            "no_changelog": True,
            "lines": [],
        }

    if resp_json.get("responseCode") != 200:
        return {
            "ok": False,
            "full_version": full_version,
            "error": f"The API returned the error code: {resp_json.get('responseCode')}",
        }

    body_str = resp_json.get("body")
    if not body_str:
        return {
            "ok": False,
            "full_version": full_version,
            "error": "The response misses the 'body' field.",
        }

    try:
        inner_data = json.loads(body_str)
    except json.JSONDecodeError:
        return {
            "ok": False,
            "full_version": full_version,
            "error": "The 'body' content is not valid JSON.",
        }

    version_name = inner_data.get("versionName")

    return {
        "ok": True,
        "full_version": full_version,
        "version_name": version_name,
        "lines": format_output(inner_data, region),
    }


def main():
    parser = argparse.ArgumentParser(
        description='ColorOS changelog query tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='\nExample:\n  python %(prog)s PHN110_11.H.19_3190\n',
    )
    parser.add_argument(
        "ota_prefix",
        metavar="OTA_Prefix",
        help='OTA prefix with two underscores (e.g. PHN110_11.H.19_3190)',
    )

    parser.add_argument("region", choices=sorted(VALID_REGIONS), help='region code')
    parser.add_argument(
        "--pre",
        type=int,
        choices=[0, 1],
        default=None,
        help=(
            "Control whether the version string contains 'PRE'.\n  1: make sure it contains PRE (add it when missing)\n  0: make sure it does not contain PRE (strip it when present)\n  When omitted the version string is used as is."
        ),
    )
    args = parser.parse_args()

    out(
        f"> Querying the changelog {args.ota_prefix.upper()}{DEFAULT_CHANGELOG_SUFFIX}\n"
    )
    try:
        result = query_changelog(args.ota_prefix, args.region, args.pre)
    except ValueError as e:
        out(f"\nError: {e}")
        return 1

    if not result["ok"]:
        out(f"Error: {result['error']}")
        return 1

    if result.get("version_name"):
        out(f"ColorOS version: {result['version_name']}\n")

    if result.get("no_changelog"):
        out('> The server has no changelog')
        return 0
    for line in result.get("lines", []):
        out(line)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        out('\n\nInterrupted by user')
        sys.exit(0)
    except Exception as e:
        out(f"\nUnknown error: {e}")
        sys.exit(1)