#!/usr/bin/env python3
"""Earbuds OTA and supported device query tool
Author: Jerry Tse
"""

# SPDX-License-Identifier: LGPL-3.0-or-later
# Derived from OPlus-Tracker (https://github.com/JerryTse-OSS/OPlus-Tracker)
# Copyright (C) Jerry Tse
# Licensed under the GNU Lesser General Public License v3.0 or later,
# see src/getrom/licenses/OPlus-Tracker/LICENSE for the full text.
# -*- coding: utf-8 -*-
import sys
import time
import uuid
import hashlib
import hmac
import requests
import argparse

from .config import EARBUDS_CONFIG

from ...log import out

def generate_headers(data_str: str, host: str, secret_key: str) -> dict:
    """Build the request headers and the HMAC-SHA1 signature."""
    time_stamp = str(int(time.time() * 1000))
    nonce = str(uuid.uuid4())
    
    sign = hmac.new(
        secret_key.encode('utf-8'), 
        data_str.encode('utf-8'), 
        hashlib.sha1
    ).hexdigest()
    
    return {
        'appid': 'earphone',
        'ts': time_stamp,
        'nonce': nonce,
        'sv': 'v1',
        'sign': sign,
        'Content-Type': 'application/json;charset=utf-8',
        'Host': host,
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'okhttp/4.6.0'
    }

def get_cn_master_list() -> dict:
    """Internal helper: fetch the global master device list from the China endpoint."""
    region_info = EARBUDS_CONFIG["regions"]["cn"]
    host = region_info["host"]
    secret_key = region_info["key"]
    
    url = f"https://{host}{EARBUDS_CONFIG['endpoints']['whitelist']}"
    data_str = '{"versionCode":"1001214","channel":"2","platform":"android"}'
    headers = generate_headers(data_str, host, secret_key)

    try:
        r = requests.post(url=url, headers=headers, data=data_str, timeout=10)
        r_json = r.json()
        if r_json.get('code') != 0:
            return {}
        
        whitelist = requests.get(r_json['data']['downloadUrl'], timeout=10).json()
        return {device["id"]: device["name"] for device in whitelist.get("compatWhiteList", [])}
    except:
        return {}

def get_devices(region: str):
    """Fetch and print the earbuds supported in a region."""
    if region != "cn":
        out(f"! Hint: {region.upper()} the regional server has no primary allowlist.")
        out('> Fetching the China global master list for reference...\n')
        devices = get_cn_master_list()
    else:
        devices = get_cn_master_list()
        
    if not devices:
        out('! Failed to fetch the allowlist')
        sys.exit(1)
        
    out(f"=== Supported device master list ===")
    for dev_id, dev_name in devices.items():
        out(f"[{dev_id}] : {dev_name}")

def query_firmware(product_id: str, region: str):
    """Query the firmware of a product id in a region."""
    region_info = EARBUDS_CONFIG["regions"][region]
    host = region_info["host"]
    secret_key = region_info["key"]
    
    url = f"https://{host}{EARBUDS_CONFIG['endpoints']['firmware_info']}"
    lang = "zh_CN" if region == "cn" else "en_US"
    data_str = '{"language":"%s","productId":"%s","versionCode":"1001214","channel":"2","platform":"android"}' % (lang, product_id)
    headers = generate_headers(data_str, host, secret_key)

    try:
        out(f"> Query: {product_id} firmware\n")
        r = requests.post(url=url, headers=headers, data=data_str, timeout=10)
        r_json = r.json()
        
        if r_json.get('code') != 0 or "data" not in r_json:
            out(f"! No update found or the request was rejected: {r_json}")
            sys.exit(1)
        
        content = r_json['data'].get('content', [])
        if not content:
            out(f"! No firmware available: {product_id} in the {region.upper()} region.")
            return

        size = content[0]['size']
        download_url = content[0]['url']
        version = r_json['data']['version']
        info = r_json['data']['updateInfo']
        device_name = r_json['data']['name']
        
        out(f"Device name: {device_name}")
        out(f"Product ID : {product_id}")
        out(f"Region     : {region.upper()}")
        out(f"Version    : {version}")
        out(f"Size       : {size} Byte")
        out(f"Link       : {download_url}")
        out(f"Changelog :{info}")
        
    except Exception as e:
        out(f"! Unknown error: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="OPPO/OnePlus Earbuds OTA Query Tool",
        epilog='Example:\n  python earbuds_query.py get\n  python earbuds_query.py 061410 cn',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "action", 
        help="'get' (list all devices) or a 6-digit product ID"
    )
    
    # The region became optional (nargs="?"), it defaults to cn
    parser.add_argument(
        "region", 
        nargs="?",
        default="cn",
        choices=["cn", "eu", "gl", "us"], 
        type=str.lower, 
        help='region code (default: cn)'
    )
    
    args = parser.parse_args()
    action = args.action.strip().lower()
    region = args.region
    
    if action == "get":
        get_devices(region)
    elif len(action) == 6 and action.isalnum():
        query_firmware(action.upper(), region)
    else:
        out('! Error: the argument must be a 6-digit product ID or get')
        sys.exit(1)

if __name__ == '__main__':
    main()
