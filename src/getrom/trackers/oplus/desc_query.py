#!/usr/bin/env python
"""OTA changelog link query tool
Author: Jerry Tse
"""

# SPDX-License-Identifier: LGPL-3.0-or-later
# Derived from OPlus-Tracker (https://github.com/JerryTse-OSS/OPlus-Tracker)
# Copyright (C) Jerry Tse
# Licensed under the GNU Lesser General Public License v3.0 or later,
# see src/getrom/licenses/OPlus-Tracker/LICENSE for the full text.
import argparse
import base64
import json
import os
import random
import string
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:
    from .config import OTA_PUBLIC_KEYS, OTA_REGION_CONFIG
except ImportError:
    out('Error: config.py not found in the current directory.')
    sys.exit(1)

DEFAULT_CHANGELOG_SUFFIX = "_197001010000"

from ...log import out, phase, warn, err


@dataclass
class QueryConfig:
    ota_prefix: str
    full_ota_version: str
    model: str
    region: str
    guid: str


def generate_random_string(length: int = 64) -> str:
    characters = string.ascii_uppercase + string.digits
    return "".join(random.choices(characters, k=length))

def generate_random_hex(length: int = 64) -> str:
    return os.urandom(length // 2).hex()

def generate_random_bytes(length: int) -> bytes:
    return os.urandom(length)

def generate_protected_key(aes_key: bytes, public_key_pem: str) -> str:
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode(), backend=default_backend()
    )
    key_b64 = base64.b64encode(aes_key)
    ciphertext = public_key.encrypt(
        key_b64,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )
    return base64.b64encode(ciphertext).decode()

def aes_ctr_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def aes_ctr_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def get_public_key_for_region(region: str) -> Tuple[str, Dict]:
    key_region = "cn" if region.startswith("cn") else region
    
    if key_region not in OTA_PUBLIC_KEYS:
        key_region = "cn" # Fallback
        
    public_key = OTA_PUBLIC_KEYS.get(key_region)
    
    if region in ["cn", "cn_cmcc", "cn_gray", "eu", "in"]:
        config = OTA_REGION_CONFIG[region]
    else:
        config = OTA_REGION_CONFIG.get("sg_host", {}).copy()
        config.update(OTA_REGION_CONFIG.get(region, {}))
        
    return public_key, config

def process_version(ota_prefix: str) -> Tuple[str, str]:
    parts = ota_prefix.split("_")
    model = parts[0].replace("PRE", "")

    if len(parts) == 3:
        full_version = f"{ota_prefix}{DEFAULT_CHANGELOG_SUFFIX}"
    else:
        full_version = ota_prefix
        
    return model, full_version

def build_request_headers(
    config: QueryConfig, region_config: Dict, device_id: str, protected_key: str
) -> Dict:
    return {
        "language": region_config.get("language", "zh-CN"),
        "newLanguage": region_config.get("language", "zh-CN"),
        "romVersion": "unknown",
        "androidVersion": "unknown",
        "colorOSVersion": "unknown",
        "infVersion": "1",
        "otaVersion": config.full_ota_version,
        "model": config.model,
        "mode": "manual",
        "nvCarrier": region_config.get("carrier_id", "10010111"),
        "pipelineKey": "ALLNET",
        "operator": "ALLNET",
        "version": "2",
        "deviceId": device_id,
        "protectedKey": json.dumps(
            {
                "SCENE_1": {
                    "protectedKey": protected_key,
                    "version": str(int(time.time() * 1000) + 1000 * 60 * 60 * 24),
                    "negotiationVersion": region_config.get("public_key_version", "1615879139745"),
                }
            }
        ),
        "Content-Type": "application/json; charset=utf-8",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "User-Agent": "okhttp/4.12.0"
    }

def query_panel_url(config: QueryConfig) -> Optional[str]:
    public_key, region_config = get_public_key_for_region(config.region)
    aes_key = generate_random_bytes(32)
    iv = generate_random_bytes(16)
    
    header_device_id = generate_random_string(64) if config.guid == "0"*64 else config.guid.upper()
    body_device_id = generate_random_hex(64) if config.guid == "0"*64 else config.guid.lower()

    headers = build_request_headers(
        config, region_config, header_device_id, generate_protected_key(aes_key, public_key)
    )

    request_body = {
        "mode": 0,
        "bigVersion": 0,
        "deviceId": body_device_id,
        "maskOtaVersion": config.full_ota_version,
        "h5LinkVersion": 6
    }
    
    cipher_text = aes_ctr_encrypt(json.dumps(request_body).encode('utf-8'), aes_key, iv)
    url = f"https://{region_config['host']}/description/v2"
    
    for attempt in range(3):
        try:
            response = requests.post(
                url,
                headers=headers,
                timeout=15,
                json={
                    "params": json.dumps(
                        {
                            "cipher": base64.b64encode(cipher_text).decode('utf-8'),
                            "iv": base64.b64encode(iv).decode('utf-8'),
                        }
                    )
                },
            )
            
            result = response.json()
            if result.get("responseCode") != 200:
                return None
                
            encrypted_body = json.loads(result.get("body", "{}"))
            if not encrypted_body:
                return None

            decrypted = aes_ctr_decrypt(
                base64.b64decode(encrypted_body["cipher"]),
                aes_key,
                base64.b64decode(encrypted_body["iv"]),
            )
            body_json = json.loads(decrypted.decode('utf-8'))
            return body_json.get("panelUrl")

        except Exception:
            if attempt == 2:
                return None
            time.sleep(2)

    return None

def main():
    parser = argparse.ArgumentParser(description="Extract panelUrl from OTA Description")
    parser.add_argument("ota_prefix", help='OTA version prefix (e.g. PJX110_11.F.16_2160)')
    parser.add_argument("region", nargs="?", default="cn", help='region code (e.g. cn, in, eu)')
    args = parser.parse_args()

    model, full_ota = process_version(args.ota_prefix)
    
    config = QueryConfig(
        ota_prefix=args.ota_prefix,
        full_ota_version=full_ota,
        model=model,
        region=args.region.lower(),
        guid="0" * 64
    )

    out(f"> Query: {config.ota_prefix}\n")

    panel_url = query_panel_url(config)

    if panel_url:
        out(f"  Changelog: {panel_url}")
    else:
        out('> No changelog found')

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit('\nInterrupted')
