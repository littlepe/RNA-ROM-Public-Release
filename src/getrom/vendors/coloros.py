# -*- coding: utf-8 -*-
"""Official OTA query for ColorOS / OPPO / OnePlus / Realme.

All three brands share one server and one scheme: the session AES key is
wrapped with RSA and the request and the response are encrypted with
AES-CTR. Both RSA and AES are implemented in pure Python, openssl is not
needed.
"""

from __future__ import print_function

import base64
import json
import os
import time

from .. import crypto
from ..log import out
from ..net import http_request

COLOROS_HOST = "component-ota-cn.allawntech.com"
COLOROS_CARRIER_ID = "10010111"
COLOROS_KEY_VERSION = "1615879139745"
COLOROS_BRANCHES = ("A", "C", "F", "H", "J")
COLOROS_MD_FILES = ("oppo_cn.md", "oneplus.md", "realme_cn.md")
# The DER key is SPKI, so it needs BEGIN PUBLIC KEY; openssl fails to parse it as RSA PUBLIC KEY.
COLOROS_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApXYGXQpNL7gmMzzvajHa
oZIHQQvBc2cOEhJc7/tsaO4sT0unoQnwQKfNQCuv7qC1Nu32eCLuewe9LSYhDXr9
KSBWjOcCFXVXteLO9WCaAh5hwnUoP/5/Wz0jJwBA+yqs3AaGLA9wJ0+B2lB1vLE4
FZNE7exUfwUc03fJxHG9nCLKjIZlrnAAHjRCd8mpnADwfkCEIPIGhnwq7pdkbamZ
coZfZud1+fPsELviB9u447C6bKnTU4AaMcR9Y2/uI6TJUTcgyCp+ilgU0JxemrSI
PFk3jbCbzamQ6Shkw/jDRzYoXpBRg/2QDkbq+j3ljInu0RHDfOeXf3VBfHSnQ66H
CwIDAQAB
-----END PUBLIC KEY-----"""


def _protect_key(aes_key):
    """Wrap the session AES key with the official RSA public key.

    Args:
        aes_key: The session AES key.

    Returns:
        str: The Base64 encoded protectedKey.
    """
    packed = crypto.rsa_oaep_encrypt_pem(base64.b64encode(aes_key), COLOROS_PUBLIC_KEY)
    return base64.b64encode(packed).decode()


def _headers(ota_version, model, mode, aes_key):
    """Build the ColorOS request headers.

    The protectedKey header carries the RSA wrapped session key.

    Args:
        ota_version: The OTA version string.
        model: The device codename.
        mode: The channel mode.
        aes_key: The session AES key.

    Returns:
        dict: The request headers.
    """
    return {
        "language": "zh-CN",
        "newLanguage": "zh-CN",
        "androidVersion": "unknown",
        "colorOSVersion": "unknown",
        "romVersion": "unknown",
        "infVersion": "1",
        "otaVersion": ota_version,
        "model": model,
        "mode": mode,
        "nvCarrier": COLOROS_CARRIER_ID,
        "pipelineKey": "ALLNET",
        "operator": "ALLNET",
        "companyId": "",
        "version": "2",
        "deviceId": os.urandom(32).hex(),
        "Content-Type": "application/json; charset=utf-8",
        "protectedKey": json.dumps(
            {
                "SCENE_1": {
                    "protectedKey": _protect_key(aes_key),
                    "version": str(time.time_ns() + 10 ** 9 * 60 * 60 * 24),
                    "negotiationVersion": COLOROS_KEY_VERSION,
                }
            }
        ),
    }


def _resolve_link(manual_url):
    """Follow the 302 of downloadCheck to get the CDN link.

    Only the Location header is read, nothing is downloaded.

    Args:
        manual_url: The original address.

    Returns:
        str: The direct link, or the original address.
    """
    from urllib.request import Request, build_opener, HTTPRedirectHandler

    class _Stop(Exception):
        """Carries the redirect Location in an exception to abort the request."""

        def __init__(self, location):
            """Remember the redirect address.

            Args:
                location: The Location header.
            """
            self.location = location

    class _NoRedirect(HTTPRedirectHandler):
        """Blocks the automatic redirect and raises _Stop instead."""

        def redirect_request(self, req, fp, code, msg, headers, newurl):
            """Intercept the redirect and raise an exception that carries the Location.

            Args:
                req: The request.
                fp: The response stream.
                code: The status code.
                msg: The status text.
                headers: The response headers.
                newurl: The redirect address.
            """
            raise _Stop(headers.get("Location") or newurl)

    try:
        opener = build_opener(_NoRedirect)
        opener.open(
            Request(
                manual_url,
                headers={
                    "User-Agent": "Mozilla/5.0 (Linux; Android 13)",
                    "userId": "oplus-ota|00000001",
                },
            ),
            timeout=15,
        )
    except _Stop as stop:
        return stop.location
    except Exception:
        return manual_url
    return manual_url


def query_branch(model, branch, anti=1):
    """Query the current firmware of one model and branch.

    Args:
        model: The device codename.
        branch: The branch.
        anti: Non zero uses the taste channel, which ColorOS 16 requires.

    Returns:
        dict: The result with code, version, link and friends.
    """
    from ..net import safe_exc

    ota_version = "{0}_11.{1}.01_0001_197001010000".format(model, branch)
    mode = "taste" if anti else "manual"
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    headers = _headers(ota_version, model, mode, aes_key)
    body = {
        "mode": "0",
        "time": int(time.time() * 1000),
        "isRooted": "0",
        "isLocked": True,
        "type": "0",
        "deviceId": os.urandom(32).hex(),
        "opex": {"check": True},
        "isSuportPki": False,
    }
    cipher = crypto.aes_ctr(json.dumps(body).encode(), aes_key, iv)
    payload = json.dumps(
        {
            "params": json.dumps(
                {
                    "cipher": base64.b64encode(cipher).decode(),
                    "iv": base64.b64encode(iv).decode(),
                }
            )
        }
    )
    url = "https://{}/update/v3".format(COLOROS_HOST)
    try:
        raw = http_request(url, data=payload, headers=headers, timeout=30)
        text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else raw
        result = json.loads(text)
    except Exception as exc:
        return {"code": "EXC", "error": safe_exc(exc)}
    if result.get("responseCode") != 200:
        return {"code": result.get("responseCode"), "error": result.get("error")}
    try:
        enc = json.loads(result["body"])
        plain = crypto.aes_ctr(
            base64.b64decode(enc["cipher"]),
            aes_key,
            base64.b64decode(enc["iv"]),
        )
        data = json.loads(plain.decode("utf-8", "replace"))
    except Exception as exc:
        return {"code": "DEC", "error": safe_exc(exc)}
    packet = {}
    for component in (data.get("components") or []):
        packet = component.get("componentPackets") or {}
        if packet.get("manualUrl"):
            break
    manual = packet.get("manualUrl") or ""
    link = _resolve_link(manual) if "downloadCheck" in manual else manual
    return {
        "code": 200,
        "version": data.get("versionName") or data.get("realVersionName"),
        "ota_version": data.get("otaVersion") or data.get("version"),
        "md5": packet.get("md5"),
        "size": packet.get("size"),
        "link": link,
    }


def query(args):
    """List the current OTA firmware of every branch of a model.

    Args:
        args: The query arguments.

    Returns:
        dict: The query result with one entry per branch.
    """
    model = (
        getattr(args, "device", "")
        or getattr(args, "codename", "")
        or getattr(args, "model", "")
        or ""
    ).strip()
    if ":" in model:
        model = model.split(":", 1)[0].strip()
    if not model:
        out("> Missing device codename")
        return {}
    branch = (getattr(args, "branch", "") or getattr(args, "channel", "") or "").strip().upper()
    branches = (branch,) if branch in COLOROS_BRANCHES else COLOROS_BRANCHES
    results = []
    for name in branches:
        result = query_branch(model, name)
        results.append(result)
        if result.get("code") == 200 and result.get("link"):
            out("> Branch: 11.{}".format(name))
            out("> Version: {}".format(result.get("version") or ""))
            out("> Package version: {}".format(result.get("ota_version") or ""))
            if result.get("md5"):
                out("> MD5: {}".format(result.get("md5")))
            if result.get("size"):
                out("> Size: {}".format(result.get("size")))
            out("> Address: {}".format(result.get("link")))
        else:
            out("> 11.{}: no package available (code={})".format(name, result.get("code")))
        time.sleep(0.5)
    return {"branches": results}
