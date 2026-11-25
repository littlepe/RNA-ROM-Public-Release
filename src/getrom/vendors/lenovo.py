# -*- coding: utf-8 -*-
"""Lenovo flash package query.

The Lenovo endpoints only accept an SN or an MTM: the SN is traded for an
MTM first, and the MTM then returns the flash packages. No model table is
built in and no cloud model list is fetched.
"""

from __future__ import print_function

import json

from ..log import out
from ..net import http_request, safe_exc

# The public Lenovo endpoints: SN to MTM to flash package.
LENOVO_DEVICE_URL = "https://ptstpd.lenovo.com.cn/home/ConfigurationQuery/getMachineSequenceInfo?MachineNo={}"
LENOVO_ROM_URL = "https://ptstpd.lenovo.com.cn/home/ConfigurationQuery/getPadFlashingMachine"
LENOVO_DEFAULT_PASSWORD = "FC(fv:SknR"


def _fetch_roms(term):
    """Query the flash packages of an MTM.

    Args:
        term: The MTM code.

    Returns:
        list: The data array.
    """
    body = json.dumps({"mtm": term})
    raw = http_request(
        LENOVO_ROM_URL,
        data=body,
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "application/json",
        },
    )
    text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else raw
    return json.loads(text).get("data") or []


def _render(item, password):
    """Print one ROM entry.

    The SN and the MTM are not shown.

    Args:
        item: The ROM entry.
        password: The archive password.
    """
    out("> Model: {}".format(item.get("product_name") or ""))
    if item.get("product_model"):
        out("> Codename: {}".format(item.get("product_model")))
    out("> Version: {}".format(item.get("latest_version") or ""))
    if item.get("server_version_name"):
        out("> File: {}".format(item.get("server_version_name")))
    out("> Address: {}".format(item.get("download_url") or ""))
    out("> Archive password: {}".format(password))


def query(args):
    """Query the Lenovo flash packages by SN or MTM.

    Args:
        args: The query arguments.

    Returns:
        dict: The query result, empty when nothing was found.
    """
    from urllib.parse import quote

    token = (
        getattr(args, "device", "")
        or getattr(args, "codename", "")
        or getattr(args, "model", "")
        or ""
    ).strip()
    sn = (getattr(args, "sn", "") or "").strip()
    if sn == "A0000000000000A":
        sn = ""

    if sn:
        # Look up the exact device with the SN of the user (never stored or echoed)
        mtm = ""
        try:
            raw = http_request(
                LENOVO_DEVICE_URL.format(quote(sn)),
                headers={"Accept": "application/json"},
            )
            text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else raw
            info = json.loads(text)
            mtm = str((info.get("data") or {}).get("MTM") or "").strip()
        except Exception as exc:
            out("> SN query failed: {}".format(safe_exc(exc)))
        if not mtm:
            out("> Could not get the model info for this SN")
            return {}
        try:
            data = _fetch_roms(mtm)
        except Exception as exc:
            out("> ROM query failed: {}".format(safe_exc(exc)))
            return {}
        if not data:
            out("> No flashable package found")
            return {}
        for item in data:
            _render(item, LENOVO_DEFAULT_PASSWORD)
        return {"packages": data}

    if not token:
        out("> Missing device codename or SN")
        return {}

    # Treat the input as an MTM.
    try:
        data = _fetch_roms(token)
    except Exception as exc:
        out("> ROM query failed: {}".format(safe_exc(exc)))
        return {}
    if not data:
        out("> No flashable package found")
        return {}
    for item in data:
        _render(item, LENOVO_DEFAULT_PASSWORD)
    return {"packages": data}
