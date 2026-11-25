# -*- coding: utf-8 -*-
"""Official upgrade query for vivo / iQOO.

Request and response are JVQ packages; ``getrom.jvq`` provides the crypto
backend (the Android helper APK or an external command).
"""

from __future__ import print_function

import random
import struct
import time
import zlib

from .. import jvq
from ..log import out
from ..net import http_request, maybe_gunzip, safe_exc, safe_preview

# The vivo upgrade endpoints: stable, redirect, taste, beta and alpha; the JVQ header token is fixed.
VIVO_OTA = "https://sysupgrade.vivo.com.cn/vgc/v2/getVgcAndPatch.do"
VIVO_REDIR = "https://sysupgrade.vivo.com.cn/pk/redirPost.do"
VIVO_TASTE = "https://sysupgrade.vivo.com.cn/upgrade/trial/getTastePk"
VIVO_BETA = "https://sysupgrade.vivo.com.cn/beta/query"
VIVO_ALPHA = "https://sysupgrade.vivo.com.cn/alpha/getAlphaState"
VIVO_TOKEN = "jnisgmain_v2@com.bbk.updater"
VIVO_HEADERS = {
    "Content-Type": "application/json; charset=utf-8",
    "User-Agent": "okhttp/4.3.23",
    "Host": "sysupgrade.vivo.com.cn",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
}


def find_vivo(device, codename, sw):
    """Resolve the vivo model from a device string, codename and software model.

    There is no model database, everything comes from the user:
    ``--device codename:software-model``.

    Args:
        device: The device string or the codename.
        codename: The codename.
        sw: The software model.

    Returns:
        dict: The model entry, None when the arguments are incomplete.
    """
    token = (device or "").strip()
    if ":" in token:
        codename, sw = token.split(":", 1)
    codename = (codename or "").strip()
    sw = (sw or "").strip()
    if codename and sw:
        return {"model": sw, "codename": codename, "sw": sw, "series": ""}
    return None


def is_phone(item, dtype=""):
    """Check whether the model is queried through the phone channel.

    Args:
        item: The model entry.
        dtype: The explicit device type.

    Returns:
        bool: True for phones.
    """
    text = (dtype or "").strip().lower()
    if text in ("phone", "1"):
        return True
    if text in ("tablet", "pad", "watch", "0"):
        return False
    series = (item.get("series") or "") + " " + (item.get("model") or "")
    if any(key in series for key in ("tablet", "wearable", "WATCH", "Watch", "Pad", "PAD")):
        return False
    if (item.get("codename") or "").startswith("DPD"):
        return False
    return True


def build_params(item, version, android, phone, is_full, channel, sn):
    """Build the parameter string of a vivo upgrade query.

    Args:
        item: The model entry.
        version: The software version.
        android: The Android version.
        phone: Whether the phone channel is used.
        is_full: Whether a full package is wanted.
        channel: The update channel.
        sn: The tablet serial number.

    Returns:
        str: The query parameters.
    """
    codename = item["codename"]
    model_sw = item["sw"]
    hw_ver = codename + "MA"
    has_w = ".W" in version
    full_sw = (version + ".V000L1") if has_w else version
    full_ver = "{}_A_{}{}".format(codename, version, ".V000L1" if has_w else "")
    version_long = "{}_N_{}MA_{}{}".format(codename, codename, version, ".V000L1" if has_w else "")
    ts = time.strftime("%y_%m_%d-%H_%M_%S")
    elapsed = (140000 + random.randint(0, 79999)) if phone else (2000000 + random.randint(0, 499999))
    params = [
        ("vgcNewActiveVer", ""),
        ("nt", "WIFI"),
        ("vgcSwVer", "1.1.1"),
        ("fullVer", full_ver),
        ("emmcid", ""),
        ("sm1", "null"),
        ("sm2", "null"),
        ("model", codename),
        ("hasVgc", 1),
        ("vgcNewPassiveVer", ""),
        ("ch", "N"),
        ("gn", 0),
        ("newActiveVer", ""),
        ("version", version_long),
        ("st2", 0),
        ("cu", "N"),
        ("srm2", 0),
        ("srm1", 0),
        ("cy", "CN-ZH"),
        ("sn2", "null"),
        ("ne", "null"),
        ("sn1", "null"),
        ("public_model", model_sw),
        ("newPassiveVer", ""),
        ("hwVer", hw_ver),
        ("swVer", full_sw),
        ("language", "zh_CN"),
        ("isMan", 1),
        ("isFull", 1 if is_full else 0),
        ("protocalversion", "1.0"),
        ("checkTrige", "MANUL"),
        ("isstlifeover", "false"),
        ("hwFingerprint", ""),
    ]
    extra = {}
    if phone:
        extra = {
            "vgcCu": "V000",
            "sf": 1,
            "si": "null",
            "dType": "phone",
            "s_n": "null",
            "elapsedtime": elapsed,
            "st1": 100000 + random.randint(0, 59999),
            "imei": "000000000000000",
            "ms": 0,
            "mtype": "no",
            "radiotype": "L",
        }
    else:
        extra = {
            "romVersion": "Funtouch {}.0".format(android),
            "occurTime": ts,
            "vgcCu": "NULL",
            "battery": 69,
            "sf": 0,
            "si": "",
            "oem": "{}_CN-ZH_FULL_SC_NULL".format(codename),
            "dType": "tablet",
            "oemProjects": "{}+{}B".format(codename, codename),
            "verName": "1.1.1.1",
            "elapsedtime": elapsed,
            "verCode": "000000001",
            "st1": 0,
            "snp": sn or "A0000000000000A",
            "imei": "",
            "sdkVersion": 34,
            "isCharge": "false",
            "ms": -1,
            "mtype": "FULL_SC",
            "radiotype": "A",
        }
    merged = []
    seen = set()
    for key, val in list(params) + list(extra.items()):
        if key in seen:
            continue
        seen.add(key)
        merged.append((key, val))
    if channel and channel != "NORMAL":
        drop = {"isMan", "protocalversion", "checkTrige", "isstlifeover"}
        merged = [(k, v) for k, v in merged if k not in drop]
        merged.extend([
            ("trigger", "verfy"),
            ("isSupportVgcTaste", 1),
            ("isSupportShowNote", 1),
            ("hwFingerprint", ""),
        ])
    return "&".join("{}={}".format(k, v) for k, v in merged)


def build_package(data):
    """Wrap data into a vivo JVQ package.

    Length, CRC32, token header and the cipher text.

    Args:
        data: The cipher text.

    Returns:
        bytes: The JVQ package.
    """
    # JVQ header: big endian length + CRC32 of the token + TLV(token=jnisgmain_v2@com.bbk.updater).
    token = VIVO_TOKEN.encode("utf-8")
    header_fields = struct.pack(">HB", 1, len(token)) + token + struct.pack(">HB", 2, 5)
    crc = zlib.crc32(header_fields) & 0xFFFFFFFF
    header_len = 16 + len(token)
    return struct.pack(">HQ", header_len, crc) + header_fields + data


def extract_body(blob):
    """Strip the header of a JVQ package.

    Args:
        blob: The JVQ package.

    Returns:
        bytes: The body to decrypt.
    """
    if not blob or len(blob) < 2:
        return blob
    header_len = struct.unpack(">H", blob[:2])[0]
    if header_len < 2 or header_len > len(blob):
        return blob
    return blob[header_len:]


def encrypt_jvq(plaintext):
    """Wrap the query plaintext into a JVQ package and encode it with the URL safe Base64 alphabet.

    Args:
        plaintext: The plaintext bytes.

    Returns:
        str: The encoded JVQ.
    """
    if not isinstance(plaintext, bytes):
        plaintext = plaintext.encode("utf-8")
    encrypted = jvq.crypt("encrypt", plaintext)
    from ..crypto import b64url

    return b64url(build_package(encrypted))


def _pkcs7_unpad(data):
    """Strip the PKCS7 padding.

    Args:
        data: The padded data.

    Returns:
        bytes: The data without padding.
    """
    if not data:
        return data
    pad = data[-1]
    if not isinstance(pad, int):
        pad = ord(pad)
    if pad < 1 or pad > 16 or len(data) < pad:
        return data
    tail = data[-pad:]
    if any((b if isinstance(b, int) else ord(b)) != pad for b in tail):
        return data
    return data[:-pad]


def _bytes_to_json_text(plain):
    """Cut the decrypted result down to the JSON text.

    Args:
        plain: The plaintext bytes.

    Returns:
        str: The JSON text.
    """
    if not isinstance(plain, bytes):
        plain = (plain or "").encode("utf-8", "replace")
    plain = _pkcs7_unpad(plain)
    start = plain.find(b"{")
    end = plain.rfind(b"}")
    chunk = plain[start:end + 1] if start >= 0 and end > start else plain
    try:
        return chunk.decode("utf-8")
    except Exception:
        return chunk.decode("utf-8", "replace")


def decrypt_response(text):
    """Decode and decrypt a vivo JVQ answer into JSON text.

    Args:
        text: The answer text.

    Returns:
        str: The JSON text.
    """
    from urllib.parse import unquote

    from ..crypto import b64mime_decode

    if isinstance(text, bytes):
        text = text.decode("ascii", "replace")
    text = (text or "").strip()
    try:
        text = unquote(text)
    except Exception:
        pass
    blob = b64mime_decode(text.replace("-", "+").replace("_", "/"))
    body = extract_body(blob)
    plain = jvq.crypt("decrypt", body)
    return _bytes_to_json_text(plain)


def post(url, plaintext):
    """Post a JVQ package to a vivo upgrade endpoint and decrypt the answer.

    Args:
        url: The endpoint URL.
        plaintext: The query plaintext.

    Returns:
        str: The decrypted JSON text.

    Raises:
        IOError: When the answer is not JVQ.
    """
    jvq_text = encrypt_jvq(plaintext)
    # The vendor expects jvq_param=<Base64URL(JVQ)> as the POST body and answers with JVQ too.
    raw = http_request(url, "jvq_param={}".format(jvq_text), VIVO_HEADERS)
    raw = maybe_gunzip(raw)
    if isinstance(raw, bytes):
        text = raw.decode("utf-8", "replace")
    else:
        text = raw
    text = (text or "").strip()
    if not (text.startswith("ACw") or text.startswith("ACo")):
        raise IOError(
            "the vivo response is not JVQ ({} chars, head={})".format(
                len(text), safe_preview(raw if isinstance(raw, (bytes, bytearray)) else text)
            )
        )
    return decrypt_response(text)


def extract_str(text, key):
    """Pick a string value out of JSON text by key.

    Args:
        text: The JSON text.
        key: The key, with or without quotes.

    Returns:
        str: The value, empty when it is not there.
    """
    if key and not key.startswith('"') and '":"' in key:
        key = '"' + key
    idx = text.find(key)
    if idx < 0:
        return ""
    start = idx + len(key)
    end = text.find('"', start)
    if end < 0:
        return ""
    return text[start:end].replace("\\/", "/")


def _clean_field(text):
    """Drop the characters that cannot be printed.

    Args:
        text: The raw text.

    Returns:
        str: The cleaned text.
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    text = text.replace("\\/", "/").strip()
    out_chars = []
    for ch in text:
        code = ord(ch)
        if 32 <= code < 127 or 0x4E00 <= code <= 0x9FFF:
            out_chars.append(ch)
    return "".join(out_chars).strip()


def _json_pick(obj, *names):
    """Pick the first non empty string of a set of candidate keys in a nested JSON.

    Args:
        obj: The JSON object.
        names: The candidate keys.

    Returns:
        str: The value, empty when it is not there.
    """
    if obj is None:
        return ""
    wanted = {name.lower() for name in names}
    found = []

    def walk(node):
        """Collect the non empty values of the candidate keys, recursively.

        Args:
            node: A JSON node.
        """
        if isinstance(node, dict):
            for key, val in node.items():
                if str(key).lower() in wanted and val not in (None, ""):
                    if isinstance(val, (str, int)):
                        found.append(str(val))
                walk(val)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(obj)
    for item in found:
        cleaned = _clean_field(item)
        if cleaned:
            return cleaned
    return ""


def pick_field(obj, *names):
    """Pick a value of a set of candidate keys in a nested dictionary.

    Args:
        obj: The dictionary.
        names: The candidate keys.

    Returns:
        object: The value, empty when it is not there.
    """
    if not isinstance(obj, dict):
        return ""
    lower = {str(k).lower(): v for k, v in obj.items()}
    for name in names:
        val = lower.get(name.lower())
        if val not in (None, ""):
            return val
    for val in obj.values():
        if isinstance(val, dict):
            found = pick_field(val, *names)
            if found:
                return found
    return ""


def json_from_text(text):
    """Try to parse the text as a JSON object.

    Args:
        text: The text.

    Returns:
        object: The parsed object, None when it fails.
    """
    import json

    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except Exception:
            return None
    return None


def pick_vivo_url(obj, text):
    """Pick the ROM download address out of the answer object or the raw text.

    Args:
        obj: The JSON object.
        text: The raw text.

    Returns:
        str: The download URL, empty when it is not there.
    """
    import re

    urls = []

    def walk(node):
        """Collect the download addresses of an object, recursively.

        Args:
            node: A JSON node.
        """
        if isinstance(node, dict):
            for key, val in node.items():
                if key.lower() in ("downloadurl", "download_url", "url", "pkgurl", "pkurl") and isinstance(val, str):
                    if val.startswith("http"):
                        urls.append(val)
                walk(val)
        elif isinstance(node, list):
            for item in node:
                walk(item)
        elif isinstance(node, str) and node.startswith("http") and (
            ".zip" in node or ".bin" in node or "ota" in node.lower()
        ):
            urls.append(node)

    if obj is not None:
        walk(obj)
    if not urls and text:
        for match in re.finditer(r"https?://[^\s\"'<>]+", text.replace("\\/", "/")):
            urls.append(match.group(0))
    for url in urls:
        if "sysdesc.vivo.com.cn" in url or "/upgrade/h5/" in url:
            continue
        return url
    # Return nothing when every candidate is a notice page, so a changelog is not
    # mistaken for a ROM download address.
    return ""


def query(args):
    """Query the official vivo upgrades.

    Prints the version, the file and the download link.

    Args:
        args: The query arguments.

    Returns:
        dict: The query result, empty when nothing was found.
    """
    item = find_vivo(
        getattr(args, "device", ""),
        getattr(args, "codename", "") or getattr(args, "model", ""),
        getattr(args, "sw", "") or getattr(args, "model", ""),
    )
    if not item:
        out("> Please specify the vivo model, e.g. --device PD2405:V2405A")
        return {}
    version = (getattr(args, "version", "") or "").strip()
    android = (getattr(args, "android", "") or "").strip()
    if android.endswith(".0"):
        android = android[:-2]
    if not version or not android:
        out("> Please enter the software version and the Android version, "
            "e.g. --version 16.1.16.5.W10 --android 16")
        return {}
    channel = (getattr(args, "channel", "") or "NORMAL").strip().upper() or "NORMAL"
    is_full = flag_on(getattr(args, "full", 1))
    if channel != "NORMAL":
        is_full = False
    phone = is_phone(item, getattr(args, "dtype", ""))
    sn = (getattr(args, "sn", "") or "A0000000000000A").strip()
    params = build_params(item, version, android, phone, is_full, channel, sn)
    kind = "full package" if is_full else "incremental package"
    out("> Querying vivo ROM: {} / {} / {} / Android {} / {} / {}".format(
        item.get("model") or item["sw"], item["codename"], version, android, kind, channel
    ))
    try:
        if channel in ("BETA", "ALPHA"):
            beta = (
                "model={}&hwVer={}MA&swVer={}&cy=CN-ZH&cu=N&dType={}&vgcCu=V000{}&romVer={}&manual=1{}"
            ).format(
                item["codename"], item["codename"], version,
                "phone" if phone else "tablet",
                "&imei=000000000000000" if phone else "&snp={}".format(sn),
                (version + ".V000L1") if ".W" in version else version,
                "&push=0" if channel == "BETA" else "",
            )
            post(VIVO_BETA if channel == "BETA" else VIVO_ALPHA, beta)
        url = VIVO_TASTE if channel != "NORMAL" else VIVO_OTA
        text = post(url, params)
    except jvq.JVQError as exc:
        out("> Request failed: {}".format(safe_exc(exc)))
        out("> The vivosign helper APK is required")
        return {}
    except Exception as exc:
        msg = safe_exc(exc)
        out("> Request failed: {}".format(msg))
        low = msg.lower()
        if any(key in low for key in ("vivosign", "libvivoseckey", "encrypt", "decrypt", "jni")):
            out("> The vivosign helper APK is required")
        return {}
    obj = json_from_text(text)
    ver = _clean_field(_json_pick(obj, "version") or extract_str(text, '"version":"'))
    name = _clean_field(_json_pick(obj, "pkName", "filename", "fileName") or extract_str(text, '"pkName":"'))
    size = _clean_field(_json_pick(obj, "pkLen", "fileSize", "size") or extract_str(text, '"pkLen":"'))
    changelog = _clean_field(_json_pick(obj, "h5Url") or extract_str(text, '"h5Url":"'))
    patch = _clean_field(
        _json_pick(obj, "securityPatch", "securityPath")
        or extract_str(text, '"securityPatch":"')
        or extract_str(text, '"securityPath":"')
    )
    md5 = _clean_field(_json_pick(obj, "md5", "fileMd5", "pkMd5") or extract_str(text, '"md5":"'))
    note = _clean_field(_json_pick(obj, "msg", "message", "note", "desc", "description"))
    pk = _clean_field(_json_pick(obj, "pk", "pkUrl", "packageUrl") or extract_str(text, '"pk":"'))
    download = ""
    if pk:
        query_text = pk.split("?", 1)[1] if "?" in pk else pk
        try:
            redir = post(VIVO_REDIR, query_text)
            redir_obj = json_from_text(redir)
            # The redirect answer often carries h5Url/sysdesc notice pages, pick_vivo_url filters them out.
            download = pick_vivo_url(redir_obj, redir)
            if not download:
                candidate = _clean_field(
                    _json_pick(redir_obj, "downloadUrl", "pkgUrl", "pkUrl", "data")
                    or extract_str(redir, '"data":"')
                )
                if candidate and "sysdesc.vivo.com.cn" not in candidate and "/upgrade/h5/" not in candidate:
                    download = candidate
        except Exception as exc:
            out("> Failed to get the download address: {}".format(exc))
    if not download:
        download = pick_vivo_url(obj, text)
    if not ver and not name and not download:
        out("> No ROM found; check the model/current software version/channel")
        if note:
            out("> Description: {}".format(note))
        preview = _clean_field(text.replace("\n", " "))
        out("> Server returned: {}".format(preview[:240]))
        return {}
    out("> Device: {}".format(item.get("model") or item["sw"]))
    out("  Codename: {}".format(item["codename"]))
    out("  Model: {}".format(item["sw"]))
    out("  Android: {}".format(android))
    out("  Channel: {}".format(channel))
    out("  Package type: {}".format(kind))
    if ver:
        out("  Software version: {}".format(ver))
    if name:
        out("  File: {}".format(name))
    if size:
        try:
            out("  Size: {} ({} MB)".format(size, int(size) // 1048576))
        except Exception:
            out("  Size: {}".format(size))
    if patch:
        out("  Security patch: {}".format(patch))
    if md5:
        out("  MD5: {}".format(md5))
    if changelog:
        out("  Update notes: {}".format(changelog.replace("/index.html", "/data/CN.js")))
    if download:
        out("  Download link: {}".format(download))
    elif name or pk:
        out("  Download link: (package info present, but the redirect address was not resolved)")
    else:
        out("  Download link: (no new package, possibly up to date)")
        if note:
            out("  Description: {}".format(note))
    return {
        "version": ver,
        "filename": name,
        "size": size,
        "security_patch": patch,
        "md5": md5,
        "changelog": changelog,
        "download": download,
    }


def flag_on(value, default=False):
    """Read a switch from text.

    Args:
        value: The text.
        default: The value used when it cannot be told apart.

    Returns:
        bool: The parsed value.
    """
    if value is None or value == "":
        return default
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on", "full", "y"):
        return True
    if text in ("0", "false", "no", "off", "n"):
        return False
    return default
