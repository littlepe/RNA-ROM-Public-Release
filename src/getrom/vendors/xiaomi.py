# -*- coding: utf-8 -*-
"""Official OTA query for Xiaomi.

Talks to the miotaV3 endpoint: the request body is a JSON document that is
AES-CBC encrypted and sent as Base64URL, and the answer is decrypted the
same way. A signed in account also reaches the firmware that is not public.
"""

from __future__ import print_function

import base64
import hashlib
import json
import os

from .. import config, crypto
from ..log import out
from ..net import http_request, safe_exc

# The Xiaomi OTA endpoint (miotaV3, China and global); the body is AES-CBC encrypted and sent as Base64URL.
XIAOMI_CN = "https://update.miui.com/updates/miotaV3.php"
XIAOMI_GL = "https://update.intl.miui.com/updates/miotaV3.php"
XIAOMI_KEY = b"miuiotavalided11"
XIAOMI_IV = b"0102030405060708"
XIAOMI_OFFICIAL = "https://ultimateota.d.miui.com/{}/{}"
XIAOMI_OFFICIAL2 = "https://superota.d.miui.com/{}/{}"
XIAOMI_CDN1 = "https://bkt-sgp-miui-ota-update-alisgp.oss-ap-southeast-1.aliyuncs.com/{}/{}"
XIAOMI_CDN2 = "https://cdnorg.d.miui.com/{}/{}"
# options.av in the body: the Updater APK version, only sent on Android 15 and newer.
XIAOMI_UPDATER_AV = "9.3.7"
# Xiaomi account login (like Updater): the credentials are traded for a serviceToken,
# the credentials live in .getrom_xiaomi_auth as accountType|base64(userId|ssecurity|
# serviceToken|cUserId|passToken); queries run signed in with s=2 plus a Cookie.
XIAOMI_AUTH_SETTING = ".getrom_xiaomi_auth"
XIAOMI_ACCOUNT_URL = "https://account.xiaomi.com"
XIAOMI_LOGIN_URL = "https://account.xiaomi.com/pass/serviceLoginAuth2"
XIAOMI_REFRESH_URL = "https://account.xiaomi.com/pass/serviceLogin"
XIAOMI_ACCOUNT_UA = (
    "Dalvik/2.1.0 (Linux; U; Android 16; 2509FPN0BC Build/BP2A.250605.031.A3)"
)
XIAOMI_SID = {"CN": "miuiromota", "GL": "miuiota_intl"}

#: Region to (codename suffix, region code).
XIAOMI_REGION = {
    "CN": ("", "CN"),
    "GL": ("_global", "MI"),
    "EEA": ("_eea_global", "EU"),
    "CL": ("_cl_global", "CL"),
    "GT": ("_gt_global", "GT"),
    "ID": ("_id_global", "ID"),
    "IN": ("_in_global", "IN"),
    "JP": ("_jp_global", "JP"),
    "KR": ("_kr_global", "KR"),
    "LM": ("_lm_global", "LM"),
    "MX": ("_mx_global", "MX"),
    "RU": ("_ru_global", "RU"),
    "TR": ("_tr_global", "TR"),
    "TW": ("_tw_global", "TW"),
    "ZA": ("_za_global", "ZA"),
}


def find_xiaomi(device):
    """Resolve the Xiaomi model from a codename.

    There is no model database, everything comes from the user.

    Args:
        device: The codename or the name.

    Returns:
        dict: The model entry, None when nothing was given.
    """
    token = (device or "").strip()
    if not token:
        return None
    return {"name": token, "codename": token, "code": ""}


def xiaomi_version(version, android, codename, region):
    """Normalise a Xiaomi version string.

    Follows the Updater rule: a leading OS1 becomes V816 (the internal HyperOS 1
    version). AUTO needs the two letter device codename of a device database,
    which this tool does not carry, so it is not expanded any more and the full
    version has to be entered.

    Args:
        version: The version text.
        android: The Android version.
        codename: The device codename.
        region: The region.

    Returns:
        str: The normalised version, empty when the version is not usable.
    """
    text = (version or "").strip().upper()
    if text.startswith("OS1"):
        text = "V816" + text[3:]
    if text.endswith("AUTO"):
        out("> AUTO is not supported, please enter the full version")
        return ""
    return text


def _xiaomi_bigversion(rom):
    """Return the major version to display.

    Like Updater: a valid osbigversion means HyperOS, a bigversion that holds 816
    means HyperOS 1.0, everything else is MIUI.

    Args:
        rom: The ROM dictionary.

    Returns:
        str: The text to show, empty when it cannot be told.
    """
    osbv = str(rom.get("osbigversion") or "").strip()
    bv = str(rom.get("bigversion") or "").strip()
    if osbv and osbv not in (".0", "0.0", "0"):
        return "HyperOS {}".format(osbv)
    if "816" in bv:
        return bv.replace("816", "HyperOS 1.0")
    if bv and bv != "0":
        return "MIUI {}".format(bv)
    return ""


def _xiaomi_changelog_lines(val):
    """Collect the text lines of one changelog category.

    Both upstream shapes are handled: {"txt": [...]} and [{txt: ...}, ...].

    Args:
        val: The changelog value of a single category.

    Returns:
        list: The text lines.
    """
    lines = []

    def add(txt):
        """Collect the text, recursively.

        Args:
            txt: The text or a list of texts.
        """
        if isinstance(txt, list):
            for item in txt:
                add(item)
        elif isinstance(txt, str) and txt.strip():
            lines.append(txt.strip())

    if isinstance(val, dict):
        add(val.get("txt"))
    elif isinstance(val, list):
        for entry in val:
            if isinstance(entry, dict):
                add(entry.get("txt"))
            else:
                add(entry)
    return lines


def print_xiaomi_rom(title, rom, official=None):
    """Print the Xiaomi ROM information.

    Version, file and download addresses.

    Args:
        title: The title.
        rom: The ROM dictionary.
        official: The (version, file name) of the official link, None when there is none.
    """
    if not rom:
        return
    version = rom.get("version") or ""
    filename = rom.get("filename") or ""
    out("> {}".format(title))
    if rom.get("device"):
        out("  Model: {}".format(rom.get("device")))
    if version:
        out("  Version: {}".format(version))
    if rom.get("codebase"):
        out("  Android: {}".format(rom.get("codebase")))
    big = _xiaomi_bigversion(rom)
    if big:
        out("  Major version: {}".format(big))
    if rom.get("type"):
        out("  Type: {}".format(rom.get("type")))
    if filename:
        out("  File: {}".format(filename))
    if rom.get("filesize"):
        out("  Size: {}".format(rom.get("filesize")))
    if version and filename:
        if official:
            out("  Official: {}".format(XIAOMI_OFFICIAL.format(official[0], official[1])))
            out("  Official 2: {}".format(XIAOMI_OFFICIAL2.format(official[0], official[1])))
        out("  CDN1: {}".format(XIAOMI_CDN1.format(version, filename)))
        out("  CDN2: {}".format(XIAOMI_CDN2.format(version, filename)))
    changelog = rom.get("changelog") or {}
    if isinstance(changelog, dict) and changelog:
        out("  Log:")
        for key, val in changelog.items():
            lines = _xiaomi_changelog_lines(val)
            if lines:
                out("    {}: {}".format(key, " / ".join(lines)))


def xiaomi_auth():
    """Read the Xiaomi login configuration.

    Returns:
        tuple: (account region, credentials), ("", None) when not signed in.
    """
    raw = config.read_setting(XIAOMI_AUTH_SETTING)
    if not raw or "|" not in raw:
        return "", None
    account_type, _, cred = raw.partition("|")
    account_type = account_type.strip().upper() or "CN"
    try:
        text = base64.b64decode(cred.strip()).decode("utf-8")
    except Exception:
        return "", None
    parts = text.split("|")
    if len(parts) < 5 or not parts[0] or not parts[2]:
        return "", None
    return account_type, {
        "userId": parts[0],
        "ssecurity": parts[1],
        "serviceToken": parts[2],
        "cUserId": parts[3],
        "passToken": parts[4],
    }


def xiaomi_save_auth(account_type, creds):
    """Save the Xiaomi login configuration.

    Args:
        account_type: The account region (CN/GL).
        creds: The credentials.

    Returns:
        bool: True when the configuration was saved.
    """
    payload = "|".join(
        str(creds.get(key, ""))
        for key in ("userId", "ssecurity", "serviceToken", "cUserId", "passToken")
    )
    token = base64.b64encode(payload.encode("utf-8")).decode("ascii")
    return config.write_setting(XIAOMI_AUTH_SETTING, "{}|{}".format(account_type, token))


def xiaomi_auth_status():
    """Return the userId of the signed in account.

    Returns:
        str: The userId, empty when not signed in.
    """
    _, creds = xiaomi_auth()
    return (creds or {}).get("userId", "")


def _parse_set_cookie(header_lines):
    """Pick the name=value pairs out of the Set-Cookie headers.

    Args:
        header_lines: The Set-Cookie header lines.

    Returns:
        dict: The cookie names and values.
    """
    cookies = {}
    for line in header_lines or []:
        first = str(line).split(";", 1)[0].strip()
        if "=" not in first:
            continue
        name, _, value = first.partition("=")
        cookies[name.strip()] = value.strip()
    return cookies


def _account_request(url, body=None, headers=None, timeout=30):
    """Call a Xiaomi account endpoint and keep the Set-Cookie headers.

    urllib is tried first, curl is the fallback.

    Args:
        url: The target URL.
        body: A form mapping or the encoded bytes, empty means GET.
        headers: Extra request headers.
        timeout: Timeout in seconds.

    Returns:
        tuple: (response text, response cookies).

    Raises:
        IOError: When urllib and curl both fail.
    """
    from urllib.parse import urlencode
    from urllib.request import Request, urlopen

    hdrs = {"User-Agent": XIAOMI_ACCOUNT_UA, "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    data = None
    if isinstance(body, dict):
        data = urlencode(body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif body:
        data = body if isinstance(body, bytes) else str(body).encode("utf-8")
    last = None
    try:
        req = Request(url, data=data, headers=hdrs)
        resp = None
        for ctx in _ssl_contexts():
            try:
                if ctx is not None:
                    resp = urlopen(req, timeout=timeout, context=ctx)
                else:
                    resp = urlopen(req, timeout=timeout)
                break
            except TypeError:
                try:
                    resp = urlopen(req, timeout=timeout)
                    break
                except Exception as exc:
                    last = exc
                    resp = None
            except Exception as exc:
                last = exc
                resp = None
        if resp is not None:
            try:
                raw = resp.read()
                try:
                    set_cookies = resp.headers.get_all("Set-Cookie")
                except Exception:
                    set_cookies = None
                if not set_cookies:
                    try:
                        set_cookies = [resp.headers["Set-Cookie"]] if resp.headers.get("Set-Cookie") else []
                    except Exception:
                        set_cookies = []
            finally:
                try:
                    resp.close()
                except Exception:
                    pass
            text = raw
            if isinstance(text, bytes):
                text = text.decode("utf-8", "replace")
            return text, _parse_set_cookie(set_cookies)
    except Exception as exc:
        last = exc
    try:
        from ..net import curl_env, find_bin
        import subprocess
        import tempfile

        curl = find_bin("curl")
        if not curl:
            raise IOError("curl not found")
        fd, hdr_path = tempfile.mkstemp(prefix="rna-acc-hdr-")
        os.close(fd)
        argv = [curl, "-sS", "-k", "-L", "--max-time", str(int(timeout)), "-D", hdr_path]
        for key, value in hdrs.items():
            argv.extend(["-H", "{}: {}".format(key, value)])
        if data is not None:
            argv.extend(["--data-binary", "@-"])
        argv.append(url)
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE if data is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=curl_env(),
        )
        out_bytes, err = proc.communicate(data, timeout=timeout + 10)
        if proc.returncode != 0:
            raise IOError((err or b"").decode("utf-8", "replace") or "curl failed")
        try:
            with open(hdr_path, "rb") as handle:
                raw_hdr = handle.read().decode("utf-8", "replace")
        finally:
            try:
                os.remove(hdr_path)
            except Exception:
                pass
        header_lines = []
        for line in raw_hdr.splitlines():
            name, sep, value = line.partition(":")
            if sep and name.strip().lower() == "set-cookie":
                header_lines.append(value.strip())
        text = out_bytes
        if isinstance(text, bytes):
            text = text.decode("utf-8", "replace")
        return text, _parse_set_cookie(header_lines)
    except Exception as exc:
        last = exc
    raise IOError("account https failed: {}".format(last))


def _ssl_contexts():
    """Build the list of usable SSL contexts.

    Returns:
        list: The contexts, None may be one of them.
    """
    from ..net import _ssl_contexts as _net_contexts

    return _net_contexts()


def _xiaomi_json(text):
    """Strip the &&&START&&& prefix of the account endpoint and parse the JSON.

    Args:
        text: The response text.

    Returns:
        dict: The parsed object, None when it fails.
    """
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    text = (text or "").strip()
    if text.startswith("&&&START&&&"):
        text = text[len("&&&START&&&"):]
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _xiaomi_service_token(location, nonce, ssecurity):
    """Trade a clientSign for a serviceToken.

    Args:
        location: The redirect address of the login answer.
        nonce: The nonce of the login answer.
        ssecurity: The session key (base64).

    Returns:
        tuple: (serviceToken, the reason it failed).
    """
    from urllib.parse import quote

    sign = ""
    if nonce:
        digest = hashlib.sha1(
            "nonce={}&{}".format(nonce, ssecurity).encode("utf-8")
        ).digest()
        sign = "&clientSign=" + quote(base64.b64encode(digest).decode("ascii"), safe="")
    url = "{}{}&_userIdNeedEncrypt=true".format(location, sign)
    try:
        _, cookies = _account_request(url, timeout=30)
    except Exception as exc:
        return "", "Request failed: {}".format(exc)
    token = cookies.get("serviceToken") or ""
    if not token:
        return "", "The response carries no serviceToken"
    return token, ""


def xiaomi_login(user, password, account_type="CN"):
    """Sign in to a Xiaomi account with a user name and a password and store the result.

    Like Updater: serviceLoginAuth2 gives the ssecurity, the passToken and the
    location, then a clientSign trades them for a serviceToken.

    Args:
        user: The account name.
        password: The password.
        account_type: The account region (CN/GL).

    Returns:
        tuple: (success, a short message).
    """
    user = (user or "").strip()
    password = password or ""
    account_type = (account_type or "CN").strip().upper()
    if account_type not in XIAOMI_SID:
        account_type = "CN"
    if not user or not password:
        return False, "Please provide the account and the password"
    form = {
        "sid": XIAOMI_SID[account_type],
        "hash": hashlib.md5(password.encode("utf-8")).hexdigest().upper(),
        "user": user,
        "_json": "true",
        "_locale": "en_US" if account_type == "GL" else "zh_CN",
    }
    try:
        text, _ = _account_request(XIAOMI_LOGIN_URL, body=form, timeout=30)
    except Exception as exc:
        return False, "Request failed: {}".format(exc)
    info = _xiaomi_json(text)
    if info is None:
        return False, "Failed to parse the login response"
    if info.get("notificationUrl"):
        return False, "This account needs two-step verification; not supported yet"
    result = str(info.get("result") or "")
    ssecurity = str(info.get("ssecurity") or "")
    if (result and result != "ok") or not ssecurity:
        reason = info.get("description") or info.get("message") or result or "Unknown error"
        return False, str(reason)
    location = str(info.get("location") or "")
    if not location:
        return False, "The login response has no redirect location"
    nonce = str(info.get("nonce") or "")
    service_token, err = _xiaomi_service_token(location, nonce, ssecurity)
    if not service_token:
        return False, err or "Failed to get the serviceToken"
    creds = {
        "userId": str(info.get("userId") or ""),
        "ssecurity": ssecurity,
        "serviceToken": service_token,
        "cUserId": str(info.get("cUserId") or ""),
        "passToken": str(info.get("passToken") or ""),
    }
    if not xiaomi_save_auth(account_type, creds):
        return False, "Failed to save the login configuration"
    return True, creds.get("userId") or user


def xiaomi_refresh_auth(account_type, creds):
    """Refresh the serviceToken with the passToken.

    Args:
        account_type: The account region (CN/GL).
        creds: The current credentials.

    Returns:
        dict: The new credentials, None when it fails.
    """
    pass_token = str((creds or {}).get("passToken") or "")
    user_id = str((creds or {}).get("userId") or "")
    if not pass_token or not user_id:
        return None
    url = "{}?sid={}&_json=true".format(
        XIAOMI_REFRESH_URL, XIAOMI_SID.get(account_type, "miuiromota")
    )
    headers = {"Cookie": "passToken={};userId={}".format(pass_token, user_id)}
    try:
        text, _ = _account_request(url, headers=headers, timeout=30)
    except Exception:
        return None
    info = _xiaomi_json(text)
    if not info:
        return None
    ssecurity = str(info.get("ssecurity") or "")
    location = str(info.get("location") or "")
    if not ssecurity or not location:
        return None
    nonce = str(info.get("nonce") or "")
    service_token, _err = _xiaomi_service_token(location, nonce, ssecurity)
    if not service_token:
        return None
    new_creds = {
        "userId": user_id,
        "ssecurity": ssecurity,
        "serviceToken": service_token,
        "cUserId": str(info.get("cUserId") or "") or str(creds.get("cUserId") or ""),
        "passToken": str(info.get("passToken") or "") or pass_token,
    }
    if xiaomi_save_auth(account_type, new_creds):
        return new_creds
    return None


def _xiaomi_request(branch, code_ext, region_code, version, android, lang, quiet=False, anon=False):
    """Build and send one miotaV3 query.

    The body is a JSON document that is AES-CBC encrypted and sent as Base64URL,
    and the answer is decrypted the same way. When an account is known the
    ssecurity of the account is used as the key and the query runs signed in
    with s=2 plus a Cookie.

    Args:
        branch: The update branch (F/X), empty means the field is left out.
        code_ext: The device codename with the region suffix.
        region_code: The region code.
        version: The normalised version.
        android: The Android version.
        lang: The language.
        quiet: Stay quiet about request and decryption errors.
        anon: Ignore the stored account and query anonymously (s=1).

    Returns:
        dict: The decrypted response JSON, None when it fails.
    """
    account_type, creds = ("", None) if anon else xiaomi_auth()
    payload = {
        "c": android,
        "d": code_ext,
        "f": "1",
        "id": "",
        "l": lang,
        "ov": version,
        "p": code_ext,
        "pn": code_ext,
        "r": region_code,
        "security": "",
        "token": "",
        "unlock": "0",
        "v": "MIUI-{}".format(version),
    }
    if creds:
        payload["id"] = str(creds.get("userId") or "")
        payload["security"] = str(creds.get("ssecurity") or "")
        payload["token"] = str(creds.get("serviceToken") or "")
    if branch:
        payload["b"] = branch
    try:
        if float(android) >= 15.0:
            payload["options"] = {"av": XIAOMI_UPDATER_AV}
    except (TypeError, ValueError):
        pass
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    if not isinstance(raw, bytes):
        raw = raw.encode("utf-8")
    key = XIAOMI_KEY
    if creds:
        try:
            decoded = base64.b64decode(str(creds.get("ssecurity") or ""))
            if len(decoded) in (16, 24, 32):
                key = decoded
        except Exception:
            key = XIAOMI_KEY
    q = crypto.b64url(crypto.aes_cbc_encrypt(raw, key, XIAOMI_IV))
    if creds:
        url = XIAOMI_CN if account_type == "CN" else XIAOMI_GL
        form = {"q": q, "t": str(creds.get("serviceToken") or ""), "s": "2"}
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Cookie": "serviceToken={}; uid={}; s=1".format(
                creds.get("serviceToken") or "", creds.get("cUserId") or ""),
        }
    else:
        url = XIAOMI_CN
        form = {"q": q, "t": "", "s": "1"}
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
    try:
        resp = http_request(url, form, headers)
    except Exception as exc:
        if not quiet:
            out("> Request failed: {}".format(safe_exc(exc)))
        return None
    try:
        plain = crypto.aes_cbc_decrypt(crypto.b64mime_decode(resp), key, XIAOMI_IV)
        text = plain.decode("utf-8") if not isinstance(plain, str) else plain
        return json.loads(text)
    except Exception:
        pass
    # When the session is refused the server answers with a plain JSON error such as {"code":2099}.
    try:
        raw_text = resp.decode("utf-8", "replace") if isinstance(resp, bytes) else str(resp)
        raw_text = (raw_text or "").strip()
        if raw_text.startswith("{"):
            data = json.loads(raw_text)
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    if not quiet:
        out("> Decryption failed: cannot parse the response")
    return None


def _xiaomi_auth_failed(info):
    """Check whether a signed in answer says the authentication failed.

    Args:
        info: The query answer, may be None.

    Returns:
        bool: True when the authentication failed.
    """
    if not isinstance(info, dict):
        return True
    if "AuthResult" in info:
        return str(info.get("AuthResult")) != "1"
    return True


def _xiaomi_official(info, code_ext, region_code, version, android, lang, anon=False):
    """Work out the version and the file name of the official link (ultimateota / superota).

    Like Updater: when the md5 of CurrentRom and LatestRom match, the file name of
    LatestRom is used; otherwise the query is sent once more without a branch to
    get LatestRom; when that fails too the official link is not available and
    only the CDN addresses are kept.

    Args:
        info: The result of the first query.
        code_ext: The device codename with the region suffix.
        region_code: The region code.
        version: The normalised version.
        android: The Android version.
        lang: The language.
        anon: Send the retry anonymously.

    Returns:
        tuple: (version, file name, whether the official link is usable).
    """
    current = info.get("CurrentRom") or {}
    latest = info.get("LatestRom") or {}
    cur_version = current.get("version") or ""
    if current.get("md5") and latest.get("filename") and current.get("md5") == latest.get("md5"):
        return cur_version, latest.get("filename"), True
    retry = _xiaomi_request("", code_ext, region_code, version, android, lang, quiet=True, anon=anon)
    latest2 = (retry or {}).get("LatestRom") or {}
    cur2 = (retry or {}).get("CurrentRom") or {}
    latest_file = latest2.get("filename") or latest.get("filename")
    retry_version = cur2.get("version") or cur_version
    if latest_file and retry_version:
        return retry_version, latest_file, True
    if current.get("filename"):
        return cur_version, current.get("filename"), False
    return "", "", False


def query(args):
    """Query the official Xiaomi OTA endpoint.

    Decrypts the answer and prints the current, the incremental and the rollback
    package.

    Args:
        args: The query arguments.

    Returns:
        dict: The query result, empty when nothing was found.
    """
    device = find_xiaomi(getattr(args, "device", "") or getattr(args, "codename", ""))
    if not device:
        out("> Please specify the Xiaomi model, e.g. --device aurora")
        return {}
    region = (getattr(args, "region", "") or "CN").strip().upper()
    if region not in XIAOMI_REGION:
        out("> Unknown region {}, available: {}".format(region, " ".join(sorted(XIAOMI_REGION))))
        return {}
    android = (getattr(args, "android", "") or "").strip()
    if android.isdigit():
        android = "{}.0".format(android)
    if not android:
        out("> Please specify the Android version, e.g. --android 15.0")
        return {}
    raw_version = (getattr(args, "version", "") or "").strip()
    version = xiaomi_version(raw_version, android, device["codename"], region)
    if not version:
        out("> Please specify the firmware version, e.g. OS2.0.2.0.VOZCNXM")
        return {}
    ext, region_code = XIAOMI_REGION[region]
    code_ext = device["codename"] + ext
    branch = (getattr(args, "branch", "") or "").strip().upper()
    if not branch:
        branch = "X" if raw_version.upper().endswith(".DEV") else "F"
    lang = "zh_CN" if "_global" not in code_ext else "en_US"
    out("> Querying Xiaomi ROM: {} / {} / {} / {}".format(
        device.get("name") or device["codename"], code_ext, version, android))
    account_type, creds = xiaomi_auth()
    if creds:
        out("> Login status: signed in ({})".format(creds.get("userId") or account_type))
    anon = False
    info = _xiaomi_request(branch, code_ext, region_code, version, android, lang)
    if info is None:
        return {}
    if creds and _xiaomi_auth_failed(info):
        out("> Login credentials expired; refreshing...")
        if not xiaomi_refresh_auth(account_type, creds):
            out("> Refresh failed; falling back to the public ROM query")
            anon = True
            info = _xiaomi_request(branch, code_ext, region_code, version, android, lang, anon=True)
            if info is None:
                return {}
        else:
            info = _xiaomi_request(branch, code_ext, region_code, version, android, lang)
            if info is None:
                return {}
            if _xiaomi_auth_failed(info):
                out("> Still invalid after refresh; falling back to the public ROM query")
                anon = True
                info = _xiaomi_request(branch, code_ext, region_code, version, android, lang, anon=True)
                if info is None:
                    return {}
    current = info.get("CurrentRom") or {}
    increment = info.get("IncrementRom") or {}
    cross = info.get("CrossRom") or {}
    found = False
    result = {}
    if current.get("filename"):
        found = True
        official = _xiaomi_official(info, code_ext, region_code, version, android, lang, anon=anon)
        print_xiaomi_rom(
            "current package", current,
            (official[0], official[1]) if official[2] else None,
        )
        result["current"] = current
    if increment.get("filename"):
        found = True
        print_xiaomi_rom(
            "incremental package", increment,
            (increment.get("version") or "", increment.get("filename")),
        )
        result["increment"] = increment
    if not current.get("filename") and not increment.get("filename") and cross.get("filename"):
        found = True
        print_xiaomi_rom(
            "cross version package", cross,
            (cross.get("version") or "", cross.get("filename")),
        )
        result["cross"] = cross
    if not found:
        out("> No public ROM found; check the model/version/region or use the full version")
    return result


def run_auth(vendor, args):
    """Run the Xiaomi account sub commands.

    Args:
        vendor: The sub command (xiaomi-login / xiaomi-auth-status / xiaomi-auth-clear).
        args: The parsed arguments.
    """
    if vendor == "xiaomi-auth-status":
        out(xiaomi_auth_status())
        return
    if vendor == "xiaomi-auth-clear":
        folder = config.settings_dir()
        path = os.path.join(folder, XIAOMI_AUTH_SETTING) if folder else ""
        if path and os.path.isfile(path):
            try:
                os.remove(path)
            except Exception as exc:
                out("> Clear failed: {}".format(exc))
                return
        out("> Logged out")
        return
    # The password comes from the environment first, so it never shows up in the command line.
    user = (getattr(args, "user", "") or "").strip()
    password = os.environ.get("XIAOMI_PASSWORD") or (getattr(args, "password", "") or "")
    account_type = (getattr(args, "acc_type", "") or "CN").strip().upper()
    ok, msg = xiaomi_login(user, password, account_type)
    out(("> Login successful: " if ok else "> Login failed: ") + str(msg))
