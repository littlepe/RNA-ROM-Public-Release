#!/usr/bin/env python
"""ColorOS downgrade package query tool
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
import sys
import time
from typing import Dict, Optional

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .config import DOWNGRADE_CONFIG

# --- Configuration ---

URL = DOWNGRADE_CONFIG["url_v2"]
NEGOTIATION_VERSION = DOWNGRADE_CONFIG["negotiation_version"]
REAL_PUB_KEY = DOWNGRADE_CONFIG["public_key"]

# --- Crypto helpers ---


from ...log import out

def get_protected_key(session_key_bytes: bytes) -> str:
    pub_key = serialization.load_pem_public_key(
        REAL_PUB_KEY.encode(), backend=default_backend()
    )
    rsa_input = base64.b64encode(session_key_bytes)
    encrypted_bytes = pub_key.encrypt(
        rsa_input,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )
    return base64.b64encode(encrypted_bytes).decode()


def encrypt_aes_gcm(plaintext: str, key: bytes, iv: bytes) -> Dict[str, str]:
    encryptor = Cipher(
        algorithms.AES(key), modes.GCM(iv), backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return {
        "cipher": base64.b64encode(ciphertext + encryptor.tag).decode(),
        "iv": base64.b64encode(iv).decode(),
    }


def decrypt_aes_gcm(cipher_b64: str, iv_b64: str, key: bytes) -> Optional[bytes]:
    try:
        full_cipher = base64.b64decode(cipher_b64)
        iv = base64.b64decode(iv_b64)
        tag, ciphertext = full_cipher[-16:], full_cipher[:-16]
        decryptor = Cipher(
            algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()
        ).decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    except Exception:
        return None


def query_downgrade(ota_prefix: str, prj_num: str, cmcc: int = 0):
    ota_version = ota_prefix.upper()
    if "_11." not in ota_version:
        ota_version = ota_version + "_11.A"
    if not prj_num.isdigit() or len(prj_num) != 5:
        raise ValueError(f"PrjNum '{prj_num}' must be exactly 5 digits.")

    model = ota_version.split("_")[0]
    duid = "0" * 64
    requests.packages.urllib3.disable_warnings()
    if cmcc == 1:
        carriers = "10011000"
    else:
        carriers = "10010111"
    # Only the first carrier value is used
    current_carrier = carriers[0]

    session_key = os.urandom(32)
    iv = os.urandom(12)
    try:
        protected_key = get_protected_key(session_key)
        encrypted_device_id_obj = encrypt_aes_gcm(duid, session_key, iv)
        payload = {
            "model": model,
            "nvCarrier": current_carrier,
            "prjNum": prj_num,
            "otaVersion": ota_version,
            "deviceId": encrypted_device_id_obj,
        }
        cipher_info = {
            "downgrade-server": {
                "negotiationVersion": NEGOTIATION_VERSION,
                "protectedKey": protected_key,
                "version": str(int(time.time())),
            }
        }
        headers = {
            "Host": "downgrade.coloros.com",
            "Content-Type": "application/json; charset=UTF-8",
            "cipherInfo": json.dumps(cipher_info),
            "deviceId": duid,
            "Connection": "close",
        }
        resp = requests.post(
            URL, headers=headers, json=payload, timeout=20, verify=False
        )
        if resp.status_code == 200:
            resp_json = resp.json()
            final_data = None
            if "cipher" in resp_json:
                decrypted_bytes = decrypt_aes_gcm(
                    resp_json["cipher"], resp_json["iv"], session_key
                )
                if decrypted_bytes:
                    try:
                        final_data = json.loads(decrypted_bytes)
                    except Exception:
                        pass
            else:
                final_data = resp_json
            if final_data and "data" in final_data and final_data["data"]:
                pkg_list = final_data["data"].get("downgradeVoList")
                if pkg_list:
                    return {
                        "ota_version": ota_version,
                        "packages": pkg_list,
                        "error": None,
                    }
            return {
                "ota_version": ota_version,
                "packages": [],
                "error": 'No downgrade package',
            }
        else:
            return {
                "ota_version": ota_version,
                "packages": [],
                "error": f"! The server returned HTTP {resp.status_code}",
            }
    except Exception as e:
        return {
            "ota_version": ota_version,
            "packages": [],
            "error": f"! Network error: {e}",
        }


def main():
    parser = argparse.ArgumentParser(
        description='ColorOS downgrade package query tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='\nExample:\n  python %(prog)s PKX110_11.C 24821\n',
    )
    parser.add_argument(
        "ota_prefix",
        metavar="OTA_Prefix",
        help='OTA prefix with an underscore (e.g. PKX110_11.C)',
    )
    parser.add_argument(
        "prj_num",
        metavar="PrjNum",
        help='project id, exactly 5 digits (e.g. 24821)',
    )
    parser.add_argument(
        "--cmcc",
        type=int,
        choices=[0, 1],
        default=0,
        help='use the mobile nvID (1) / do not use it (0) (default: 0)',
    )
    args = parser.parse_args()

    result = query_downgrade(args.ota_prefix, args.prj_num, args.cmcc)
    out(f"> Querying the downgrade package: {result['ota_version']}\n")
    if result["packages"]:
        pkg_list = result["packages"]
        for i, pkg in enumerate(pkg_list):
            out('> Result:')
            out(f"  Link: {pkg.get('downloadUrl', 'Unknown')}")
            out(f"  Changelog: {pkg.get('versionIntroduction', 'Unknown')}")
            out(
                f"  Version: {pkg.get('colorosVersion', '')} ({pkg.get('androidVersion', '')})"
            )
            out(f"  OTA version: {pkg.get('otaVersion', 'Unknown')}")
            out(f"  MD5: {pkg.get('fileMd5', 'Unknown')}")
            file_size = pkg.get("fileSize")
            if file_size is not None:
                try:
                    size_mb = float(file_size) / 1024 / 1024
                    out(f"  File size: {file_size} Byte ({size_mb:.0f}M)")
                except Exception:
                    out(f"  File size: {file_size} Byte (unknown)")
            else:
                out('  File size: unknown')
            if i < len(pkg_list) - 1:
                out()
        return 0
    out(result["error"] or 'No downgrade package')
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        out('\n\nInterrupted by user')
        sys.exit(0)
    except Exception as e:
        out(f"\nUnknown error: {str(e)}")
        sys.exit(1)