# -*- coding: utf-8 -*-
"""Cloud OTA query for Obric devices.

A JSON body plus an X-Signature header: ak:HMAC-SHA256(sk, "POST\\n\\n" + MD5(body)).
"""

from __future__ import print_function

import base64
import hashlib
import hmac
import json
import os

from .. import config
from ..log import out
from ..net import as_bytes, download, http_request, size_text

# The Obric cloud OTA endpoint.
OBRIC_ENDPOINT = "https://cloud.oceancloudapi.com/os/device/ota/check"
OBRIC_PRODUCTS = {
    "pacific": {
        "product": "Pacific",
        "product_name": "Pacific",
        "model": "P0110",
        "ak": "Pacific",
        "sk": "b01b44e861fd3a62e767f43500cf6a4c",
    },
    "ocean2": {
        "product": "Ocean2",
        "product_name": "Ocean2",
        "model": "taro",
        "ak": "Ocean2",
        "sk": "96b9b5e1dae1afc428c1315c2fc6374c",
    },
}
OBRIC_ALIASES = {
    "pacific": "pacific",
    "p0110": "pacific",
    "ocean2": "ocean2",
    "ocean": "ocean2",
    "taro": "ocean2",
    "obric": "pacific",
}

#: Default current system version, same as the GUI preset.
DEFAULT_OS_VERSION = "1.0.0.0"
#: Default ROM version, same as the GUI preset.
DEFAULT_ROM_VERSION = "1.0.0.0-20251122-153043-RELEASE-user-pacific-b402"
#: Default build timestamp, same as the GUI preset.
DEFAULT_BUILD_TIME = "1763796643"


def resolve_product(args):
    """Resolve the user input into an Obric product configuration.

    Args:
        args: The query arguments.

    Returns:
        dict: The product configuration, None when it is unknown.
    """
    token = (
        getattr(args, "device", "")
        or getattr(args, "codename", "")
        or getattr(args, "model", "")
        or ""
    ).strip()
    if ":" in token:
        token = token.split(":", 1)[0].strip()
    key = OBRIC_ALIASES.get(token.lower())
    if key:
        return dict(OBRIC_PRODUCTS[key])
    return None


def sign(secret, body):
    """Compute the HMAC-SHA256 signature of an Obric OTA request.

    Args:
        secret: The secret key.
        body: The request body.

    Returns:
        str: The Base64 signature.
    """
    digest = hashlib.md5(as_bytes(body)).hexdigest()
    text = "POST\n\n{}\n".format(digest)
    raw = hmac.new(as_bytes(secret), as_bytes(text), hashlib.sha256).digest()
    return base64.b64encode(raw).decode("ascii")


def build_body(product, os_version, rom_version, build_time, udid, flag, build_type, language, country):
    """Build the body of an Obric OTA check request.

    Args:
        product: The product configuration.
        os_version: The system version.
        rom_version: The ROM version.
        build_time: The build time.
        udid: The device unique id.
        flag: The OTA flag.
        build_type: The build type.
        language: The language.
        country: The country.

    Returns:
        str: The compact JSON body.
    """
    return json.dumps(
        {
            "product": product["product"],
            "product_name": product["product_name"],
            "model": product["model"],
            "udid": udid,
            "os_version": os_version,
            "buildtype": build_type,
            "buildtime": build_time,
            "rom_version": rom_version,
            "flag": flag,
            "did": "",
            "language": language,
            "country_code": country,
        },
        separators=(",", ":"),
        ensure_ascii=False,
    )


def query_once(product, os_version, rom_version, build_time, udid, flag, build_type, language, country,
               timeout=30):
    """Run one OTA check against the Obric cloud.

    Args:
        product: The product configuration.
        os_version: The system version.
        rom_version: The ROM version.
        build_time: The build time.
        udid: The device unique id.
        flag: The OTA flag.
        build_type: The build type.
        language: The language.
        country: The country.
        timeout: Timeout in seconds.

    Returns:
        dict: The response JSON.

    Raises:
        IOError: When the response is not valid.
    """
    body = build_body(
        product, os_version, rom_version, build_time, udid, flag, build_type, language, country
    )
    headers = {
        "Cache-Control": "no-cache",
        "Content-Type": "application/json",
        "User-Agent": "okhttp/3",
        # Vendor header: AccessKey plus HMAC-SHA256(SecretKey, "POST\n\n" + MD5(JSON)).
        "X-Signature": "{}:{}".format(product["ak"], sign(product["sk"], body)),
    }
    raw = http_request(OBRIC_ENDPOINT, data=body, headers=headers, timeout=timeout)
    text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else raw
    try:
        result = json.loads(text)
    except Exception:
        raise IOError("The OTA server returned invalid JSON: {}".format(text[:240]))
    if not isinstance(result, dict):
        raise IOError("The OTA server returned an unexpected JSON")
    return result


def extract_packages(result):
    """Extract the package list from an OTA response.

    Args:
        result: The response JSON.

    Returns:
        list: The package dictionaries.
    """
    data = result.get("data")
    if not isinstance(data, dict):
        return []
    packages = data.get("package")
    if not isinstance(packages, list):
        return []
    return [item for item in packages if isinstance(item, dict)]


def choose_package(packages):
    """Pick the OTA package.

    A full package (type 1) wins, otherwise the first entry is used.

    Args:
        packages: The package list.

    Returns:
        dict: The chosen package, None when the list is empty.
    """
    for item in packages:
        if str(item.get("type")) == "1":
            return item
    return packages[0] if packages else None


def next_build(package):
    """Derive the version triple of the next hop from the current package.

    Args:
        package: The package dictionary.

    Returns:
        tuple: (version, name, buildtime).

    Raises:
        IOError: When a required field is missing.
    """
    version = str(package.get("version") or "").strip()
    name = os.path.basename(str(package.get("name") or "").strip())
    if name.lower().endswith(".zip"):
        name = name[:-4]
    build_time = str(package.get("buildtime") or "").strip()
    if not version or not name or not build_time:
        raise IOError("The package misses version / name / buildtime")
    return version, name, build_time


def print_package(product, package):
    """Print the Obric ROM information.

    Version, size and download address.

    Args:
        product: The product configuration.
        package: The package dictionary.
    """
    ver = str(package.get("version") or "")
    name = str(package.get("name") or "")
    size = package.get("size")
    md5 = str(package.get("md5") or "")
    url = str(package.get("url") or "")
    build_time = str(package.get("buildtime") or "")
    out("> Device: {}".format(product.get("product") or ""))
    out("  Model: {}".format(product.get("model") or ""))
    if ver:
        out("  Software version: {}".format(ver))
    if name:
        out("  File: {}".format(name))
    if size not in (None, ""):
        out("  Size: {} ({})".format(size, size_text(size)))
    if build_time:
        out("  Build time: {}".format(build_time))
    if md5:
        out("  MD5: {}".format(md5))
    if url:
        out("  Download link: {}".format(url))
    else:
        out("  Download link: (no new package)")


def download_dir(raw):
    """Turn the download argument into a target directory.

    Args:
        raw: The value of --download.

    Returns:
        str: The directory, empty when nothing should be downloaded.
    """
    text = (raw or "").strip()
    if not text or text.lower() in ("0", "false", "no", "off", "n"):
        return ""
    if text.lower() in ("1", "true", "yes", "on", "y"):
        return (
            os.getenv("WORK_PRO")
            or os.getenv("RNA_PRO")
            or os.getenv("DNA_PRO")
            or os.getenv("WORK_DIR")
            or os.getenv("RNA_DIR")
            or config.data_dir()
        )
    return text


def verify_package(path, package):
    """Verify a downloaded file against the MD5 of the server.

    Args:
        path: The file path.
        package: The package dictionary.

    Raises:
        IOError: When the MD5 does not match.
    """
    expected = str(package.get("md5") or "").strip().lower()
    if not expected:
        out("> The server provided no MD5; skipping verification")
        return
    out("> Verify MD5: {}".format(path))
    digest = hashlib.md5()
    with open(path, "rb") as stream:
        while True:
            chunk = stream.read(8 * 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    actual = digest.hexdigest()
    if actual != expected:
        raise IOError("MD5 mismatch: got {}, expected {}".format(actual, expected))
    out("> MD5 OK: {}".format(actual))


def query(args):
    """Walk the OTA chain and collect the Obric ROMs.

    Downloads and verifies them when asked to.

    Args:
        args: The query arguments.

    Returns:
        dict: The query result, empty when nothing was found.
    """
    product = resolve_product(args)
    if not product:
        out("> Please select an Obric model: Pacific / Ocean2")
        out("> Example: getrom obric --device Pacific --version 1.0.0.0")
        return {}
    os_version = (
        getattr(args, "version", None) or getattr(args, "os_version", None) or DEFAULT_OS_VERSION
    ).strip() or DEFAULT_OS_VERSION
    rom_version = (
        getattr(args, "rom_version", None)
        or getattr(args, "sw", None)
        or DEFAULT_ROM_VERSION
    ).strip()
    build_time = (getattr(args, "build_time", None) or DEFAULT_BUILD_TIME).strip()
    udid = (
        getattr(args, "udid", None) or getattr(args, "sn", None) or "000000000000000"
    ).strip() or "000000000000000"
    flag = str(getattr(args, "flag", None) or "1").strip() or "1"
    build_type = (
        getattr(args, "build_type", None) or getattr(args, "channel", None) or "user"
    ).strip() or "user"
    if build_type.upper() in ("NORMAL", "TRIAL", "BETA", "ALPHA"):
        build_type = "user"
    language = (getattr(args, "language", None) or "zh").strip() or "zh"
    country = (getattr(args, "region", None) or getattr(args, "country", None) or "CN").strip() or "CN"
    follow = flag_on(getattr(args, "full", "1"), True)
    target = (getattr(args, "target_version", None) or "").strip()
    try:
        max_hops = int(getattr(args, "max_hops", None) or 10)
    except Exception:
        max_hops = 10
    if max_hops < 1:
        max_hops = 1
    dest = download_dir(getattr(args, "download", None) or "")
    verify = flag_on(getattr(args, "verify", "1"), True)
    seen_builds = set()
    seen_versions = set()
    packages = []
    current = (os_version, rom_version, build_time)
    try:
        for hop in range(1, max_hops + 1):
            if current in seen_builds:
                out("> OTA chain loop: {}".format(current[0]))
                break
            seen_builds.add(current)
            out("> Query {}: current={}".format(hop, current[0]))
            result = query_once(
                product, current[0], current[1], current[2],
                udid, flag, build_type, language, country,
            )
            package = choose_package(extract_packages(result))
            if package is None:
                code = result.get("code")
                message = result.get("message") or "no update"
                out("> No update: code={}, message={}".format(code, message))
                break
            version = str(package.get("version") or "")
            if version in seen_versions:
                break
            seen_versions.add(version)
            packages.append(package)
            print_package(product, package)
            if target and version == target:
                break
            if not follow:
                break
            current = next_build(package)
        else:
            out("> Reached max hops: {}".format(max_hops))
    except Exception as exc:
        out("> Query failed: {}".format(exc))
        return {}
    if not packages:
        out("> No Obric ROM found; check the model/current version")
        return {}
    if target:
        last_ver = str((packages[-1] or {}).get("version") or "")
        if last_ver != target:
            out("> Target version not found {}, last returned {}".format(target, last_ver or "none"))
            return {}
    if dest:
        package = packages[-1]
        try:
            url = str(package.get("url") or "")
            name = os.path.basename(str(package.get("name") or "").strip())
            if not url or not name:
                raise IOError("The package has no download URL or file name")
            try:
                expect = int(package.get("size") or 0)
            except Exception:
                expect = 0
            path = download(url, dest, filename=name, expect_size=expect)
            if verify:
                verify_package(path, package)
        except Exception as exc:
            out("> Download failed: {}".format(exc))
    return {"packages": packages}


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
    if text in ("1", "true", "yes", "on", "y"):
        return True
    if text in ("0", "false", "no", "off", "n"):
        return False
    return default
