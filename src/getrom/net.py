# -*- coding: utf-8 -*-
"""HTTP requests and file downloads.

The standard library ``urllib`` is tried first and an external ``curl`` takes
over when it fails, which keeps things working on Android builds without a
usable TLS stack. Every path and command lookup is cross platform.
"""

from __future__ import print_function

import gzip
import os
import shutil
import subprocess
import time
import zlib

try:
    from io import BytesIO as _BytesIO
except ImportError:  # pragma: no cover - Python 2 compatibility
    from StringIO import StringIO as _BytesIO

from . import config
from .log import debug, out

#: Default request headers.
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 RNA-ROM getrom",
    "Accept": "*/*",
}


def _urlencode(data):
    """Encode form data into a query string.

    Args:
        data: A mapping or a sequence of key value pairs.

    Returns:
        bytes: The encoded data.
    """
    from urllib.parse import urlencode

    text = urlencode(data)
    if isinstance(text, bytes):
        return text
    return text.encode("utf-8")


def as_bytes(data):
    """Turn a request body into bytes.

    Args:
        data: None, a mapping, bytes or a string.

    Returns:
        bytes: The encoded body; None stays None.
    """
    if data is None:
        return None
    if isinstance(data, dict):
        return _urlencode(data)
    if isinstance(data, bytes):
        return data
    if isinstance(data, bytearray):
        return bytes(data)
    return str(data).encode("utf-8")


def maybe_gunzip(raw):
    """Try to gunzip or inflate a response by looking at its magic bytes.

    Args:
        raw: The raw response data.

    Returns:
        bytes: The decompressed data, or the input when it is not compressed.
    """
    if not raw or not isinstance(raw, (bytes, bytearray)):
        return raw
    data = bytes(raw)
    if data[:2] == b"\x1f\x8b":
        try:
            return gzip.GzipFile(fileobj=_BytesIO(data)).read()
        except Exception:
            return raw
    if len(data) >= 2 and data[0] == 0x78 and data[1] in (0x01, 0x5E, 0x9C, 0xDA):
        try:
            return zlib.decompress(data)
        except Exception:
            return raw
    return raw


def find_bin(name):
    """Look for an executable.

    The ``RNA_BIN`` directory, the package directory and the system ``PATH``
    are searched in that order.

    Args:
        name: The executable name.

    Returns:
        str: The path, or an empty string when it is not found.
    """
    rnabin = os.environ.get("RNA_BIN") or ""
    here = os.path.dirname(os.path.abspath(__file__))
    paths = []
    if rnabin:
        paths.append(os.path.join(rnabin, name))
    paths.append(os.path.join(here, name))
    paths.append(os.path.join(here, "lib", name))
    for path in paths:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    try:
        found = shutil.which(name)
        if found:
            return found
    except Exception:
        pass
    return ""


def clean_env():
    """Build a clean environment for the external commands.

    On Android/Termux the library paths that clash with the bundled tools are
    dropped; every other platform keeps the current environment.

    Returns:
        dict: The environment variables.
    """
    env = os.environ.copy()
    if not config.is_android():
        return env
    parts = []
    for item in (env.get("LD_LIBRARY_PATH") or "").split(os.pathsep):
        if not item:
            continue
        norm = item.replace("\\", "/").rstrip("/")
        if (
            norm.endswith("/tools/lib")
            or norm.endswith("/runtime/bin/lib")
            or "/com.rna.tools/" in norm
        ):
            continue
        parts.append(item)
    termux = "/data/user/0/com.termux/files/usr"
    termux_lib = os.path.join(termux, "lib")
    if os.path.isdir(termux_lib):
        parts = [termux_lib] + [p for p in parts if p != termux_lib]
        env["PATH"] = os.path.join(termux, "bin") + os.pathsep + env.get("PATH", "")
    if parts:
        env["LD_LIBRARY_PATH"] = os.pathsep.join(parts)
    else:
        env.pop("LD_LIBRARY_PATH", None)
    env.pop("LD_PRELOAD", None)
    return env


def _bin_lib_dirs():
    """Return the lib directories of the bundled tools.

    Returns:
        list: The directories that exist.
    """
    dirs = []
    for base in (os.environ.get("RNA_BIN") or "", os.path.dirname(os.path.abspath(__file__))):
        if not base:
            continue
        lib = os.path.join(base, "lib")
        if os.path.isdir(lib) and lib not in dirs:
            dirs.append(lib)
    return dirs


def curl_env():
    """Build the environment for the bundled curl.

    Returns:
        dict: The environment variables.
    """
    env = clean_env()
    libs = _bin_lib_dirs()
    if libs:
        cur = env.get("LD_LIBRARY_PATH") or ""
        env["LD_LIBRARY_PATH"] = os.pathsep.join(libs + ([cur] if cur else []))
    return env


def _ssl_contexts():
    """Build the list of usable SSL contexts.

    Returns:
        list: The contexts, None may be one of them.
    """
    ctxs = []
    try:
        import ssl
    except Exception:
        return [None]
    try:
        ctxs.append(ssl.create_default_context())
    except Exception:
        pass
    try:
        ctxs.append(ssl._create_unverified_context())
    except Exception:
        pass
    if not ctxs:
        ctxs.append(None)
    return ctxs


def http_urllib(url, body, headers, timeout):
    """Send a request with urllib.

    Args:
        url: The target URL.
        body: The request body.
        headers: The request headers.
        timeout: Timeout in seconds.

    Returns:
        bytes: The response data.
    """
    from urllib.request import Request, urlopen

    req = Request(url, data=body, headers=headers)
    last = None
    resp = None
    for ctx in _ssl_contexts():
        try:
            if ctx is not None:
                resp = urlopen(req, timeout=timeout, context=ctx)
            else:
                resp = urlopen(req, timeout=timeout)
            break
        except TypeError:
            resp = urlopen(req, timeout=timeout)
            break
        except Exception as exc:
            last = exc
            resp = None
    if resp is None:
        raise last or IOError("urlopen failed")
    try:
        data = resp.read()
    finally:
        try:
            resp.close()
        except Exception:
            pass
    return maybe_gunzip(data)


def http_curl(url, body, headers, timeout):
    """Send a request with curl.

    Args:
        url: The target URL.
        body: The request body.
        headers: The request headers.
        timeout: Timeout in seconds.

    Returns:
        bytes: The response data.

    Raises:
        IOError: When curl is missing or fails.
    """
    curl = find_bin("curl")
    if not curl:
        raise IOError("curl not found")
    argv = [
        curl, "-sS", "-k", "--compressed", "-L",
        "--max-time", str(int(timeout)),
        "-A", headers.get("User-Agent") or "RNA-ROM",
    ]
    has_auth = False
    for key, val in headers.items():
        if key.lower() in ("user-agent", "accept-encoding"):
            continue
        if key.lower() == "authorization":
            has_auth = True
        argv.extend(["-H", "{}: {}".format(key, val)])
    # With authentication the Authorization header has to survive a cross host redirect.
    if has_auth:
        argv.append("--location-trusted")
    if body is not None:
        argv.extend(["--data-binary", "@-"])
    argv.append(url)
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE if body is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=curl_env(),
    )
    raw, err = proc.communicate(body, timeout=timeout + 5)
    if proc.returncode != 0:
        raise IOError((err or b"").decode("utf-8", "replace") or "curl failed")
    return maybe_gunzip(raw)


def http_request(url, data=None, headers=None, timeout=30):
    """Send an HTTP request.

    urllib is tried first, curl is the fallback.

    Args:
        url: The target URL.
        data: The request body.
        headers: The request headers.
        timeout: Timeout in seconds.

    Returns:
        bytes: The response data.

    Raises:
        IOError: When both implementations fail.
    """
    body = as_bytes(data)
    hdrs = dict(DEFAULT_HEADERS)
    if headers:
        hdrs.update(headers)
    last = None
    try:
        return http_urllib(url, body, hdrs, timeout)
    except Exception as exc:
        last = exc
        debug("urllib failed: {}".format(exc))
    try:
        return http_curl(url, body, hdrs, timeout)
    except Exception as exc:
        last = exc
        debug("curl failed: {}".format(exc))
    raise IOError("https failed: {}".format(last))


def http_text(url, data=None, headers=None, timeout=30):
    """Send a request and decode the answer as UTF-8.

    Args:
        url: The target URL.
        data: The request body.
        headers: The request headers.
        timeout: Timeout in seconds.

    Returns:
        str: The response text.
    """
    raw = http_request(url, data=data, headers=headers, timeout=timeout)
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw).decode("utf-8", "replace")
    return str(raw)


def download(url, dest_dir, filename="", headers=None, timeout=30, expect_size=0, on_progress=None):
    """Download a file, resuming over HTTP Range when possible.

    Args:
        url: The download URL.
        dest_dir: The target directory.
        filename: The file name; taken from the URL when empty.
        headers: Extra request headers.
        timeout: Timeout in seconds.
        expect_size: The expected size, 0 when unknown.
        on_progress: Progress callback, receives (bytes done, total bytes).

    Returns:
        str: The path of the downloaded file.

    Raises:
        IOError: When the download fails or the size does not match.
    """
    from urllib.error import HTTPError
    from urllib.request import Request, urlopen

    name = filename or os.path.basename(url.split("?")[0]) or "download.bin"
    if not os.path.isdir(dest_dir):
        os.makedirs(dest_dir)
    output = os.path.join(dest_dir, name)
    existing = os.path.getsize(output) if os.path.isfile(output) else 0
    if expect_size and existing > expect_size:
        raise IOError("The existing file is larger than expected: {} ({} > {})".format(
            output, existing, expect_size))
    if expect_size and existing == expect_size:
        out("> Download complete: {}".format(output))
        return output
    hdrs = {"User-Agent": "RNA-ROM getrom"}
    if headers:
        hdrs.update(headers)
    if existing:
        hdrs["Range"] = "bytes={}-".format(existing)
    req = Request(url, headers=hdrs)
    try:
        resp = urlopen(req, timeout=timeout)
    except HTTPError as error:
        raise IOError("Download HTTP {}".format(getattr(error, "code", "")))
    except Exception as error:
        raise IOError("Download failed: {}".format(error))
    status = getattr(resp, "status", None) or getattr(resp, "code", None) or resp.getcode()
    append = existing > 0 and int(status) == 206
    if existing and not append:
        existing = 0
    downloaded = existing
    started = time.time()
    last_report = started
    out("> {} download: {}".format("Resume" if append else "Start", output))
    try:
        with open(output, "ab" if append else "wb") as stream:
            while True:
                chunk = resp.read(8 * 1024 * 1024)
                if not chunk:
                    break
                stream.write(chunk)
                downloaded += len(chunk)
                now = time.time()
                if now - last_report >= 1.0:
                    speed = (downloaded - existing) / max(now - started, 0.001)
                    if on_progress:
                        on_progress(downloaded, expect_size)
                    else:
                        out("  {}  {}/s".format(size_text(downloaded), size_text(int(speed))))
                    last_report = now
    finally:
        try:
            resp.close()
        except Exception:
            pass
    actual = os.path.getsize(output)
    if expect_size and actual != expect_size:
        raise IOError("Download incomplete: got {}, expected {}".format(actual, expect_size))
    out("> Download complete: {}".format(output))
    return output


def size_text(size):
    """Format a byte count with a unit.

    Args:
        size: The number of bytes.

    Returns:
        str: The readable text.
    """
    try:
        size = int(size)
    except Exception:
        return str(size or "")
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024.0 or unit == "TiB":
            if unit == "B":
                return "{} B".format(size)
            return "{:.2f} {}".format(value, unit)
        value /= 1024.0
    return "{} B".format(size)


def safe_exc(exc, limit=240):
    """Turn an exception into text that is safe to show.

    Args:
        exc: The exception.
        limit: The maximum length.

    Returns:
        str: The text; binary payloads are summarised.
    """
    text = "" if exc is None else str(exc)
    if not text:
        return "unknown"
    repl = text.count("\ufffd")
    ctrl = sum(1 for ch in text[:limit] if ord(ch) < 32 and ch not in "\t\n\r")
    if repl >= 4 or ctrl >= 4:
        return "Non-text response ({} chars)".format(len(text))
    return text[:limit]


def safe_preview(raw, n=12):
    """Build a short hex preview of a response.

    Args:
        raw: The raw data.
        n: The number of preview bytes.

    Returns:
        str: The preview text.
    """
    if raw is None:
        return "empty"
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "replace")
    if not raw:
        return "empty"
    if raw[:2] == b"\x1f\x8b":
        return "gzip {}".format(raw[:n].hex())
    return raw[:n].hex()


__all__ = [
    "http_request",
    "http_text",
    "download",
    "as_bytes",
    "maybe_gunzip",
    "find_bin",
    "size_text",
    "safe_exc",
    "safe_preview",
]
