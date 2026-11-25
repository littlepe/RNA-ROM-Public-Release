#!/usr/bin/env python3
"""Vivo / iQOO OTA query (VIVO-OTA-Tracker).

A pure Python implementation: the AES-128-CBC parameters were recovered from
libvivoseckey_n4.so, so the JVQ messages can be encrypted and decrypted
locally without the VivoSign helper app.
"""

# SPDX-License-Identifier: Apache-2.0
# Derived from VIVO-OTA-Tracker
# (https://github.com/JerryTse-OSS/VIVO-OTA-Tracker,
#  https://github.com/mytiantian001/VIVO-OTA-Tracker-Android)
# Licensed under the Apache License, Version 2.0,
# see src/getrom/licenses/VIVO-OTA-Tracker/LICENSE for the full text.
import argparse
import base64
import binascii
import gzip
import json
import os
import random
import re
import sys
import time
import uuid
import zlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode, quote_plus, quote

import ssl
import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context
from cryptography.hazmat.primitives import padding as _aes_padding
from cryptography.hazmat.primitives.ciphers import Cipher as _aes_cipher
from cryptography.hazmat.primitives.ciphers import algorithms as _aes_algorithms
from cryptography.hazmat.primitives.ciphers import modes as _aes_modes

# Mute the SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# A custom SSL adapter, used for compatibility
from ..log import out

class SSLAdapter(HTTPAdapter):
    """A custom HTTP adapter that keeps the SSL setup under control."""

    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers('DEFAULT:@SECLEVEL=1')
        kwargs['ssl_context'] = ctx
        return super().init_poolmanager(*args, **kwargs)


# ============================================================
# Constants
# ============================================================

TOKEN_NATIVE = "jnisgmain_v2@com.bbk.updater"

# AES-128-CBC parameters, taken from the shared object
AES_IV = bytes.fromhex("047cd76d65d3b28b4ccc2c0246681aa6")
AES_KEY_KV1 = bytes.fromhex("5da590863052089893199b2a901b6470")
AES_KEY_KV2 = bytes.fromhex("836e75afddae728551ad22b2bae6ca57")
PUB_KEY_HASH = "077c62d0246d6572d2760e3247a1ebcaf68eb4161aa13353583c445ce71fc49c"

# API endpoints
BASE_URL = "https://sysupgrade.vivo.com.cn"
UPDATE_ENDPOINT = "/vgc/v2/getVgcAndPatch.do?"
REDIR_ENDPOINT = "/pk/redirPost.do"


# ============================================================
# Data classes
# ============================================================

@dataclass
class DeviceConfig:
    """The device configuration of an OTA query."""
    device_type: str = "phone"
    model_sw_ver: str = "PD2408"
    device_model: str = "V2408A"
    sw_version: str = "16.1.16.5.W10"
    android_ver: int = 16
    snp: str = "A0000000000000A"
    is_full: bool = True
    verbose: bool = False


@dataclass
class UpdateInfo:
    """The parsed OTA update information."""
    version: Optional[str] = None
    filename: Optional[str] = None
    size: Optional[str] = None
    size_mb: Optional[int] = None
    download_url: Optional[str] = None
    changelog_url: Optional[str] = None
    raw_response: Optional[str] = None


# ============================================================
# Crypto helpers
# ============================================================

def aes_encrypt(plaintext: bytes, key_version: int = 2) -> bytes:
    """Encrypt data with AES-128-CBC and PKCS7 padding.

    Args:
        plaintext: The data to encrypt.
        key_version: The key version (1 or 2).

    Returns:
        bytes: The encrypted data.
    """
    key = AES_KEY_KV1 if key_version == 1 else AES_KEY_KV2
    padder = _aes_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = _aes_cipher(_aes_algorithms.AES(key), _aes_modes.CBC(AES_IV)).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def aes_decrypt(ciphertext: bytes, key_version: int = 2) -> bytes:
    """Decrypt data with AES-128-CBC and PKCS7 padding.

    Args:
        ciphertext: The data to decrypt.
        key_version: The key version (1 or 2).

    Returns:
        bytes: The decrypted data.
    """
    key = AES_KEY_KV1 if key_version == 1 else AES_KEY_KV2
    decryptor = _aes_cipher(_aes_algorithms.AES(key), _aes_modes.CBC(AES_IV)).decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = _aes_padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted) + unpadder.finalize()


# ============================================================
# Protocol helpers
# ============================================================

def build_protocol_package(
    msg_type: int,
    key_version: int,
    token: str,
    data: bytes
) -> bytes:
    """Build the protocol package with its header and the encrypted payload.

    Args:
        msg_type: The message type (5 means encrypted).
        key_version: The key version (1 or 2).
        token: The protocol token.
        data: The encrypted payload.

    Returns:
        bytes: The complete protocol package.
    """
    token_bytes = token.encode("utf-8")
    header_total_len = 16 + len(token_bytes)

    # Build the header fields
    header_fields = bytearray()
    header_fields += (1).to_bytes(2, "big")  # The version number
    header_fields += len(token_bytes).to_bytes(1, "big")
    header_fields += token_bytes
    header_fields += key_version.to_bytes(2, "big")
    header_fields += msg_type.to_bytes(1, "big")

    # The CRC32 of the header fields
    crc = zlib.crc32(header_fields) & 0xFFFFFFFF

    # Build the full package
    package = bytearray()
    package += header_total_len.to_bytes(2, "big")
    package += crc.to_bytes(8, "big")
    package += header_fields
    package += data

    return bytes(package)


def extract_encrypted_body(full_package: bytes) -> bytes:
    """Take the encrypted payload out of a protocol package.

    Args:
        full_package: The complete protocol package.

    Returns:
        bytes: The encrypted payload.
    """
    header_len = int.from_bytes(full_package[:2], "big")
    return full_package[header_len:]


def base64_url_encode(data: bytes) -> str:
    """Encode bytes into a URL safe base64 string."""
    return base64.urlsafe_b64encode(data).decode("ascii")


def base64_url_decode(data: str) -> bytes:
    """Decode a URL safe base64 string into bytes."""
    from urllib.parse import unquote
    # Decode the URL first, the same way Java URLDecoder.decode does
    decoded = unquote(data)
    # Then swap in the URL safe base64 characters
    decoded = decoded.replace("-", "+").replace("_", "/")
    # Add the padding when it is missing
    pad_len = 4 - len(decoded) % 4
    if pad_len != 4:
        decoded += "=" * pad_len
    return base64.b64decode(decoded)


def encrypt_to_jvq(plaintext: str, key_version: int = 2) -> str:
    """Encrypt the plaintext into the jvq_param format.

    Args:
        plaintext: The text to encrypt.
        key_version: The key version (1 or 2).

    Returns:
        str: The protocol package, encoded with the URL safe base64 alphabet.
    """
    plaintext_bytes = plaintext.encode("utf-8")
    encrypted = aes_encrypt(plaintext_bytes, key_version)
    package = build_protocol_package(5, key_version, TOKEN_NATIVE, encrypted)
    return base64_url_encode(package)


def decrypt_response(response_b64: str, key_version: int = 2) -> str:
    """Decrypt a base64 encoded answer.

    Args:
        response_b64: The answer, encoded with the URL safe base64 alphabet.
        key_version: The key version (1 or 2).

    Returns:
        str: The decrypted plaintext.
    """
    full_package = base64_url_decode(response_b64)
    encrypted_body = extract_encrypted_body(full_package)
    decrypted = aes_decrypt(encrypted_body, key_version)
    return decrypted.decode("utf-8")


# ============================================================
# HTTP helpers
# ============================================================

def http_post(url: str, body: str, timeout: int = 60, max_retries: int = 3) -> str:
    """Send an HTTP POST request with retries.

    Args:
        url: The address.
        body: The request body.
        timeout: The timeout in seconds.
        max_retries: The maximum number of retries.

    Returns:
        str: The response body.
    """
    # Exactly the same Content-Type as the Java version
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": "okhttp/4.3.23",
        "Host": "sysupgrade.vivo.com.cn",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
    }

    # Create the session with the custom SSL adapter
    session = requests.Session()
    session.mount("https://", SSLAdapter())

    last_error = None
    for attempt in range(max_retries):
        try:
            response = session.post(
                url,
                data=body.encode("utf-8"),
                headers=headers,
                timeout=(10, timeout),  # (connect timeout, read timeout)
                verify=False,
            )
            response.raise_for_status()

            # Read the raw content
            content = response.content

            # Try to decompress when it looks like gzip
            if len(content) >= 2 and content[:2] == b'\x1f\x8b':
                try:
                    content = gzip.decompress(content)
                except Exception:
                    pass  # Not gzip, keep it as it is

            # Try a few encodings
            for encoding in ['utf-8', 'gbk', 'gb2312', 'latin-1']:
                try:
                    return content.decode(encoding)
                except (UnicodeDecodeError, LookupError):
                    continue

            return content.decode('utf-8', errors='replace')

        except (requests.exceptions.SSLError, requests.exceptions.ConnectionError) as e:
            last_error = e
            if attempt < max_retries - 1:
                wait_time = 2 * (attempt + 1)
                out(f"  ! Connection error, retrying in {wait_time}s... ({attempt + 1}/{max_retries})")
                time.sleep(wait_time)
            continue

        except requests.exceptions.Timeout as e:
            last_error = e
            if attempt < max_retries - 1:
                wait_time = 5 * (attempt + 1)
                out(f"  ! Timeout, retrying in {wait_time}s... ({attempt + 1}/{max_retries})")
                time.sleep(wait_time)
            continue

        except requests.exceptions.RequestException as e:
            last_error = e
            break

    raise last_error


def send_encrypted_request(plaintext: str, key_version: int = 2) -> str:
    """Send an encrypted request to the OTA server.

    Args:
        plaintext: The request plaintext.
        key_version: The key version (1 or 2).

    Returns:
        str: The decrypted response.
    """
    jvq_param = encrypt_to_jvq(plaintext, key_version)
    url = BASE_URL + UPDATE_ENDPOINT
    response = http_post(url, "jvq_param=" + jvq_param)

    if not response.startswith(("ACw", "ACo")):
        return "[Error] " + response

    return decrypt_response(response, key_version)


def request_redir_post(plaintext: str, key_version: int = 2) -> str:
    """Send the redirect POST request.

    Args:
        plaintext: The request plaintext.
        key_version: The key version (1 or 2).

    Returns:
        str: The decrypted response.
    """
    jvq_param = encrypt_to_jvq(plaintext, key_version)
    url = BASE_URL + REDIR_ENDPOINT
    response = http_post(url, "jvq_param=" + jvq_param)

    if not response.startswith(("ACw", "ACo")):
        return "[Error] " + response

    return decrypt_response(response, key_version)


# ============================================================
# Helpers
# ============================================================

def generate_imei() -> str:
    """Build a random 15 digit IMEI string."""
    return "".join(str(random.randint(0, 9)) for _ in range(15))


def extract_json_str(json_str: str, key: str) -> str:
    """Pick a string value out of JSON with a simple pattern match.

    Args:
        json_str: The JSON text.
        key: The key pattern to look for, for example ``'pk":"'``.

    Returns:
        str: The value, ``"(Not found)"`` when there is none.
    """
    idx = json_str.find(key)
    if idx < 0:
        return "(Not found)"

    start = idx + len(key)
    end = json_str.find('"', start)

    if end < 0:
        end = json_str.find(",", start)
        if end < 0:
            end = json_str.find("}", start)
        return json_str[start:end].strip()

    return json_str[start:end]

def join_params(params: Dict[str, str]) -> str:
    """Join a parameter mapping into a URL query string.

    Args:
        params: The parameter mapping.

    Returns:
        str: The joined parameters.
    """
    return "&".join(f"{k}={v}" for k, v in params.items())


def normalize_json_url(url: Optional[str]) -> Optional[str]:
    """Normalise a URL that was escaped for JSON."""
    if url is None:
        return None
    return url.replace("\\/", "/")


def parse_size(size_str: str) -> int:
    """Parse a size string into an integer."""
    try:
        return int(size_str)
    except (ValueError, TypeError):
        return 0


# ============================================================
# Request building
# ============================================================

def build_request_params(config: DeviceConfig) -> Dict[str, str]:
    """Build the request parameters of an OTA query.

    Args:
        config: The device configuration.

    Returns:
        dict: The parameter mapping.
    """
    is_phone = config.device_type == "phone"

    # Derived values
    hw_ver = config.model_sw_ver + "MA"

    if ".W" in config.sw_version:
        full_sw_version = config.sw_version + ".V000L1"
        full_ver = f"{config.model_sw_ver}_A_{config.sw_version}.V000L1"
        version_long = f"{config.model_sw_ver}_N_{config.model_sw_ver}MA_{config.sw_version}.V000L1"
    else:
        full_sw_version = config.sw_version
        full_ver = f"{config.model_sw_ver}_A_{config.sw_version}"
        version_long = f"{config.model_sw_ver}_N_{config.model_sw_ver}MA_{config.sw_version}"

    ts = time.strftime("%y_%m_%d-%H_%M_%S")
    elapsedtime = (
        140000 + random.randint(0, 80000)
        if is_phone
        else 2000000 + random.randint(0, 500000)
    )
    is_full = 1 if config.is_full else 0
    imei = generate_imei()

    # Common parameters
    params = {
        "vgcNewActiveVer": "",
        "nt": "WIFI",
        "vgcSwVer": "1.1.1",
        "fullVer": full_ver,
        "emmcid": "",
        "sm1": "null",
        "sm2": "null",
        "model": config.model_sw_ver,
        "hasVgc": 1,
        "vgcNewPassiveVer": "",
        "ch": "N",
        "gn": 0,
        "newActiveVer": "",
        "version": version_long,
        "st2": 0,
        "cu": "N",
        "srm2": 0,
        "srm1": 0,
        "cy": "CN-ZH",
        "sn2": "null",
        "ne": "null",
        "sn1": "null",
        "public_model": config.device_model,
        "newPassiveVer": "",
        "hwVer": hw_ver,
        "swVer": full_sw_version,
        "language": "zh_CN",
        "isMan": 1,
        "isFull": is_full,
        "protocalversion": "1.0",
        "checkTrige": "MANUL",
        "isstlifeover": "false",
        "hwFingerprint": "",
    }

    # Device specific parameters
    if is_phone:
        params.update({
            "vgcCu": "V000",
            "sf": 1,
            "si": "null",
            "dType": "phone",
            "s_n": "null",
            "elapsedtime": elapsedtime,
            "st1": 100000 + random.randint(0, 60000),
            "imei": imei,
            "ms": 0,
            "mtype": "no",
            "radiotype": "L",
        })
    else:
        params.update({
            "romVersion": f"Funtouch {config.android_ver}.0",
            "occurTime": ts,
            "vgcCu": "NULL",
            "battery": 69,
            "sf": 0,
            "si": "",
            "oem": f"{config.model_sw_ver}_CN-ZH_FULL_SC_NULL",
            "dType": "tablet",
            "oemProjects": f"{config.model_sw_ver}+{config.model_sw_ver}B",
            "verName": "1.1.1.1",
            "elapsedtime": elapsedtime,
            "verCode": "000000001",
            "st1": 0,
            "snp": config.snp,
            "imei": "",
            "sdkVersion": 34,
            "isCharge": "false",
            "ms": -1,
            "mtype": "FULL_SC",
            "radiotype": "A",
        })

    return params

def parse_update_response(response: str, config: DeviceConfig = None) -> UpdateInfo:
    """Parse an update answer into an UpdateInfo.

    Args:
        response: The decrypted response text.
        config: The device configuration, used for the redirect parameters.

    Returns:
        UpdateInfo: The parsed result.
    """
    info = UpdateInfo(raw_response=response)

    info.version = extract_json_str(response, 'version":"')
    info.filename = extract_json_str(response, 'pkName":"')
    info.size = extract_json_str(response, 'pkLen":"')
    info.size_mb = parse_size(info.size) // 1048576 if info.size != "(Not found)" else 0
    info.changelog_url = extract_json_str(response, 'h5Url":"')

    # Take the download address from the pk field through redirPost.do
    info.download_url = "https://sysuptxdl.vivo.com.cn/upgrade/oem/files/" + extract_json_str(response, 'pkName":"')
    return info


# ============================================================
# Display helpers
# ============================================================

def print_update_info(info: UpdateInfo) -> None:
    """Print the update information in the formatted layout."""
    out('=== Update info ===')

    if info.version and info.version != "(Not found)":
        out(f"  Version: {info.version}")

    if info.filename and info.filename != "(Not found)":
        out(f"  File name: {info.filename}")

    if info.size and info.size != "(Not found)":
        out(f"  Size: {info.size} bytes ({info.size_mb} MB)")

    if info.download_url:
        out(f"  Download link: {info.download_url}")

    if info.changelog_url and info.changelog_url != "(Not found)":
        out(f"  Changelog: {info.changelog_url}")


# ============================================================
# The main query function
# ============================================================

def query_ota_update(config: DeviceConfig) -> Optional[UpdateInfo]:
    """Query the OTA updates of a device.

    Args:
        config: The device configuration.

    Returns:
        UpdateInfo: The parsed result on success, None on failure.
    """
    # Build the request parameters
    params = build_request_params(config)
    raw_params = join_params(params)

    out(f"  Device: {config.device_type} | {config.device_model} / {config.model_sw_ver}")
    out(f"  Base version: {config.sw_version}")

    if config.verbose:
        out(f"  Raw request parameters: {raw_params}")

    # Send the encrypted request
    try:
        response = send_encrypted_request(raw_params)
    except Exception as e:
        out(f"  ! Request failed: {e}")
        return None

    if config.verbose:
        out(f"\n  Raw response: {response}")

    # Check the errors
    if response.startswith("[Error]"):
        out(f"  {response}")
        return None
    elif "210" in response:
        out(f"\n  ! No update found for this device")
        return None
    
    # Parse the response
    info = parse_update_response(response, config)
    print_update_info(info)

    return info


# ============================================================
# Command line entry point
# ============================================================

def print_usage():
    """Print the usage examples when no argument is given."""
    out('\nUsage: python vivo_ota_tracker.py [options]\n\nRequired options:\n  -t, --device-type   device type: phone or tablet\n  -m, --model         software model code (e.g. PD2408, DPD2106)\n  -d, --device        device model (e.g. V2408A, PA2170)\n  -v, --version       current software version (e.g. 16.1.16.5.W10, 8.7.22)\n  -a, --android-ver   Android / OriginOS major version (e.g. 16, 14)\n  --isfull            full package flag: true or false\n\nOptional options:\n  --snp               serial number (default: A0000000000000A)\n  --verbose           print the raw request / response for debugging\n\nExamples:\n  # phone query (full package)\n  python vivo_ota_tracker.py -t phone -m PD2408 -d V2408A -v 16.1.16.5.W10 -a 16 --isfull true\n\n  # tablet query (incremental package)\n  python vivo_ota_tracker.py -t tablet -m DPD2106 -d PA2170 -v 8.7.22 -a 14 --isfull false --verbose\n')


def parse_args() -> argparse.Namespace:
    """Parse the command line arguments."""
    parser = argparse.ArgumentParser(
        description='Vivo / iQOO OTA query (VIVO-OTA-Tracker)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='\nExamples:\n  # phone query (full package)\n  %(prog)s -t phone -m PD2408 -d V2408A -v 16.1.16.5.W10 -a 16 --isfull true\n\n  # tablet query (incremental package)\n  %(prog)s -t tablet -m DPD2106 -d PA2170 -v 8.7.22 -a 14 --isfull false --verbose\n        ',
    )

    parser.add_argument(
        "-t", "--device-type",
        required=True,
        choices=["phone", "tablet"],
        help='device type',
    )
    parser.add_argument(
        "-m", "--model",
        required=True,
        help='software model code (e.g. PD2408, DPD2106)',
    )
    parser.add_argument(
        "-d", "--device",
        required=True,
        help='device model (e.g. V2408A, PA2170)',
    )
    parser.add_argument(
        "-v", "--version",
        required=True,
        help='current software version (e.g. 16.1.16.5.W10, 8.7.22)',
    )
    parser.add_argument(
        "-a", "--android-ver",
        required=True,
        type=int,
        help='Android / OriginOS major version (e.g. 16, 14)',
    )
    parser.add_argument(
        "--isfull",
        required=True,
        choices=["true", "false"],
        help='full package flag: true or false',
    )
    parser.add_argument(
        "--snp",
        default="A0000000000000A",
        help='serial number (default: A0000000000000A)',
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help='print the raw request / response for debugging',
    )

    return parser.parse_args()


def main() -> int:
    """The main entry point."""
    # Show the usage when no argument is given
    if len(sys.argv) == 1:
        print_usage()
        return 0

    args = parse_args()

    # Build the configuration
    config = DeviceConfig(
        device_type=args.device_type,
        model_sw_ver=args.model,
        device_model=args.device,
        sw_version=args.version,
        android_ver=args.android_ver,
        snp=args.snp,
        is_full=args.isfull == "true",
        verbose=args.verbose,
    )

    # Query the OTA updates
    info = query_ota_update(config)

    if info is None:
        return 1

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        out('  ! Interrupted by user')
        sys.exit(130)
    except Exception as e:
        out(f"\n  ! Fatal error: {e}")
        sys.exit(1)
