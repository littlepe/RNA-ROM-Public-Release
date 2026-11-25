# -*- coding: utf-8 -*-
"""Cloud OTA query for StepAOS / StepX.

The endpoint takes an x-www-form-urlencoded POST signed with OAuth 1.0 and
HMAC-SHA256.
"""

from __future__ import print_function

import base64
import hashlib
import hmac
import json
import time
import uuid

from ..log import out
from ..net import as_bytes, http_request

# StepAOS / StepX (MzUpdate, package com.stepos.update) cloud OTA:
# an OAuth 1.0 HMAC-SHA256 signature over an x-www-form-urlencoded POST.
STEPAOS_ENDPOINT = "https://upush.stepaos.com/v4/firmware/check"
STEPAOS_CONSUMER_KEY = "kB0GuUVISDjfGnzR2uSU"
STEPAOS_SECRET = "pSo9LOJlVYqBmYsYQfXWxIdgt5et2Q"
STEPAOS_UA = "okhttp/3.12.13"
# Known devices: deviceType -> (display_id, android_version).
# The display_id comes from ro.build.aios_version in system_build.prop.
STEPAOS_DEVICES = {
    "pz261a": {
        "device_type": "PZ261A",
        "display_id": "Step AOS 1.0.0.2.26001_stable_user_20261004_131555",
        "android": "16",
    },
}
STEPAOS_ALIASES = {
    "pz261a": "pz261a",
    "stepaos": "pz261a",
    "stepx": "pz261a",
}


def resolve_device(args):
    """Resolve the user input into a StepAOS device configuration.

    Args:
        args: The query arguments.

    Returns:
        dict: The device configuration, None when it is unknown.
    """
    token = (
        getattr(args, "device", "")
        or getattr(args, "codename", "")
        or getattr(args, "model", "")
        or ""
    ).strip()
    if ":" in token:
        token = token.split(":", 1)[0].strip()
    key = STEPAOS_ALIASES.get(token.lower())
    if key:
        return dict(STEPAOS_DEVICES[key])
    return None


def _encode(value):
    """Java URLEncoder.encode(value, "UTF-8") followed by RequestManager.paramEncode.

    Args:
        value: The raw string.

    Returns:
        str: The encoded text.
    """
    from urllib.parse import quote_plus

    text = quote_plus(str(value), safe="")
    return text.replace("+", "%20").replace("*", "%2A").replace("~", "%7E")


def sign(url, params, secret):
    """Compute the OAuth 1.0 HMAC-SHA256 signature of a StepAOS OTA request.

    base = "POST|" + java_urlencode(url) + "|" +
           "&".join(sorted("name=java_urlencode(value)")) + "|" + secret + "|"

    Args:
        url: The request URL.
        params: The request parameters without oauth_signature.
        secret: The OAuth secret.

    Returns:
        str: The Base64 signature.
    """
    parts = []
    for name in sorted(params):
        parts.append(name + "=" + _encode(params[name]))
    base = "POST|{}|{}|{}|".format(_encode(url), "&".join(parts), secret)
    raw = hmac.new(as_bytes(secret), as_bytes(base), hashlib.sha256).digest()
    return base64.b64encode(raw).decode("ascii")


def check(device, display_id, android, firmware_type=None, timeout=60):
    """Run one firmware check against the StepAOS cloud.

    Args:
        device: The device configuration.
        display_id: The current system version (sysVer / version).
        android: The Android version.
        firmware_type: The wanted firmware type (stable / beta / daily), omitted when empty.
        timeout: Timeout in seconds.

    Returns:
        dict: The response JSON.

    Raises:
        IOError: When the response is not valid.
    """
    sys_obj = {
        "isCheckCdnBandwidth": False,
        "retryCheckCounts": 0,
        "unitType": "0",
        # oaid / dsid / ppid: the server only wants non empty values, so random ones are fine.
        "oaid": uuid.uuid4().hex[:16],
        "dsid": uuid.uuid4().hex[:16],
        "ppid": uuid.uuid4().hex[:16],
        "deviceType": device["device_type"],
        "firmware": android,
        "root": 0,
        "sysVer": display_id,
        "version": display_id,
    }
    if firmware_type:
        sys_obj["targetFirmwareType"] = firmware_type
    params = {
        "sys": json.dumps(sys_obj, separators=(",", ":"), ensure_ascii=False),
        "oauth_consumer_key": STEPAOS_CONSUMER_KEY,
        "oauth_timestamp": str(int(time.time())),
        "oauth_version": "1.0",
        "oauth_signature_method": "HMAC-SHA256",
    }
    params["oauth_signature"] = sign(STEPAOS_ENDPOINT, params, STEPAOS_SECRET)
    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "User-Agent": STEPAOS_UA,
        "isCheckCdnBandWidth": "false",
        "retryCheckCounts": "0",
    }
    raw = http_request(STEPAOS_ENDPOINT, data=params, headers=headers, timeout=timeout)
    text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else raw
    try:
        result = json.loads(text)
    except Exception:
        raise IOError("The OTA server returned invalid JSON: {}".format(text[:240]))
    if not isinstance(result, dict):
        raise IOError("The OTA server returned an unexpected JSON")
    return result


def print_firmware(label, item):
    """Print one StepAOS firmware entry.

    Args:
        label: The label of the entry (current / update).
        item: The firmware dictionary.
    """
    version = str(item.get("latestVersion") or "")
    release_date = str(item.get("releaseDate") or "")
    size = item.get("fileSize") or item.get("size")
    url = str(item.get("updateUrl") or "")
    digest = str(item.get("digest") or "")
    digest_v2 = str(item.get("digestV2") or "")
    mandatory = item.get("mandatoryUpgrade")
    out("> {}: {}".format(label, version or "(none)"))
    if release_date:
        out("  Release date: {}".format(release_date))
    if size not in (None, ""):
        out("  Size: {}".format(size))
    if mandatory:
        out("  Force upgrade: yes")
    if digest:
        out("  MD5: {}".format(digest))
    if digest_v2:
        out("  SHA256: {}".format(digest_v2))
    if url:
        out("  Download link: {}".format(url))


def query(args):
    """Query the StepAOS / StepX firmware updates.

    Args:
        args: The query arguments.

    Returns:
        dict: The query result, empty when the query failed.
    """
    device = resolve_device(args)
    if not device:
        out("> Please select a StepAOS model: PZ261A")
        out("> Example: getrom stepaos --device PZ261A")
        return {}
    display_id = (getattr(args, "version", "") or device.get("display_id", "")).strip()
    if not display_id:
        out('> Please provide the current system version, e.g. --version '
            '"Step AOS 1.0.0.2.26001_stable_user_20261004_131555"')
        return {}
    android = (getattr(args, "android", "") or device.get("android", "16")).strip() or "16"
    channel = (getattr(args, "channel", "") or "").strip().lower()
    if channel in ("", "normal"):
        firmware_type = None
    else:
        firmware_type = channel
    try:
        result = check(device, display_id, android, firmware_type)
    except Exception as exc:
        out("> Query failed: {}".format(exc))
        return {}
    reply = result.get("reply") if isinstance(result, dict) else None
    if isinstance(reply, dict):
        code = reply.get("code")
        message = reply.get("message") or ""
        value = reply.get("value") or {}
    else:
        code = result.get("code")
        message = result.get("message") or ""
        value = {}
    if str(code) != "200":
        out("> Query failed: code={}, message={}".format(code, message))
        return {}
    out("> Device: {}".format(device.get("device_type") or ""))
    out("  Android: {}".format(android))
    out("  Current version: {}".format(display_id))
    cur = value.get("cur") or {}
    new = value.get("new") or {}
    if cur:
        print_firmware("Current", cur)
    if new:
        print_firmware("Update", new)
    else:
        out("> Already up to date; no update on this channel")
    return {"current": cur, "new": new}
