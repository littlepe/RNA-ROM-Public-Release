# -*- coding: utf-8 -*-
"""vivo JVQ crypto backends.

The vivo upgrade endpoint exchanges JVQ packages, and the crypto relies on the
vendor JNI (``libvivoseckey.so``), which cannot be reimplemented in pure
Python. Three backends are available:

* External command: ``GETROM_VIVO_CRYPT_CMD`` points at a command that reads
  the payload from stdin and writes the result to stdout; ``{op}`` is
  replaced by ``encrypt`` / ``decrypt``. Works on every platform.
* Android script: runs ``tools/vivo_jvq/jvq.sh`` on Android, the script drives
  the ``com.rna.vivosign`` helper APK.
* Android helper APK: launches the helper APK with ``am start`` directly,
  the same way RNA-ROM does it.
"""

from __future__ import print_function

import base64
import os
import subprocess
import time

from . import config
from .log import debug

#: Environment variable of the external command backend.
CRYPT_CMD_ENV = "GETROM_VIVO_CRYPT_CMD"

#: Environment variable and relative path of the Android script backend.
SCRIPT_ENV = "VIVO_JVQ_SCRIPT"
SCRIPT_REL = os.path.join("tools", "vivo_jvq", "jvq.sh")

#: Package name and activity of the Android helper APK.
HELPER_PACKAGE = "com.rna.vivosign"
HELPER_ACTIVITY = "com.rna.tools.VivoJvqActivity"

#: Input and output locations of the Android helper APK.
HELPER_CACHE = "/data/user/0/com.rna.vivosign/cache"
HELPER_OUT = HELPER_CACHE + "/.vivosign.out"
HELPER_OUT_EXT = "/storage/emulated/0/Android/data/com.rna.vivosign/files/.vivosign.out"
HELPER_OUT_MEDIA = "/data/media/0/Android/data/com.rna.vivosign/files/.vivosign.out"


class JVQError(RuntimeError):
    """Raised when the JVQ crypto fails."""


def _command_crypt(op, data):
    """Run the external command to encrypt or decrypt.

    Args:
        op: encrypt or decrypt.
        data: The input data.

    Returns:
        bytes: The result.

    Raises:
        JVQError: When the command is missing or fails.
    """
    template = (os.getenv(CRYPT_CMD_ENV) or "").strip()
    if not template:
        raise JVQError("The external command backend is not configured")
    if "{op}" in template:
        argv = [part.format(op=op) for part in _split_command(template)]
    else:
        argv = _split_command(template) + [op]
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        raw, err = proc.communicate(data, timeout=60)
    except Exception as exc:
        raise JVQError("External command failed: {}".format(exc))
    if proc.returncode != 0:
        raise JVQError((err or b"").decode("utf-8", "replace").strip() or "External command failed")
    if raw[:6] == b"error:":
        raise JVQError(raw.decode("utf-8", "replace").strip())
    if not raw:
        raise JVQError("The external command returned no data")
    return raw


def _split_command(template):
    """Split a command line the way a shell does.

    Args:
        template: The command text.

    Returns:
        list: The arguments.
    """
    import shlex

    try:
        return shlex.split(template, posix=(os.name != "nt"))
    except Exception:
        return template.split()


def _script_crypt(op, data):
    """Run the Android script to encrypt or decrypt.

    Args:
        op: encrypt or decrypt.
        data: The input data.

    Returns:
        bytes: The result.

    Raises:
        JVQError: When the script is missing or fails.
    """
    script = helper_script()
    if not script:
        raise JVQError("The vivo JVQ script was not found")
    last = None
    # The script may not be executable (files checked out on Windows), fall back to sh.
    for argv in ([script, op], ["sh", script, op]):
        try:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            raw, err = proc.communicate(data, timeout=180)
        except OSError as exc:
            last = exc
            continue
        except Exception as exc:
            raise JVQError("The vivo JVQ script failed: {}".format(exc))
        if proc.returncode != 0:
            raise JVQError(
                (err or b"").decode("utf-8", "replace").strip() or "The vivo JVQ script failed"
            )
        if raw[:6] == b"error:":
            raise JVQError(raw.decode("utf-8", "replace").strip())
        if not raw:
            raise JVQError("The vivo JVQ script returned no data")
        return raw
    raise JVQError("The vivo JVQ script failed: {}".format(last))


def _android_env():
    """Build the environment used to call the helper APK.

    Returns:
        dict: The environment variables.
    """
    env = os.environ.copy()
    env.pop("LD_LIBRARY_PATH", None)
    env.pop("LD_PRELOAD", None)
    old_path = env.get("PATH") or ""
    env["PATH"] = "/system/bin:/system/xbin" + ((":" + old_path) if old_path else "")
    if not env.get("ANDROID_ROOT"):
        env["ANDROID_ROOT"] = "/system"
    if not env.get("ANDROID_DATA"):
        env["ANDROID_DATA"] = "/data"
    return env


def _am_cmds(args):
    """Build the am / cmd activity commands that are available.

    Args:
        args: The am sub command arguments.

    Returns:
        list: The commands.
    """
    cmds = []
    if os.path.isfile("/system/bin/am"):
        cmds.append(["/system/bin/am"] + args)
    if os.path.isfile("/system/bin/cmd"):
        cmds.append(["/system/bin/cmd", "activity"] + args)
    return cmds


def _helper_installed(env):
    """Check whether the helper APK is installed.

    Args:
        env: The environment for the child process.

    Returns:
        bool: True when it is installed.
    """
    try:
        for cmd in (
            ["/system/bin/pm", "path", HELPER_PACKAGE],
            ["/system/bin/cmd", "package", "path", HELPER_PACKAGE],
        ):
            if not os.path.isfile(cmd[0]):
                continue
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env
            )
            raw, _ = proc.communicate(timeout=10)
            if b"package:" in (raw or b""):
                return True
    except Exception:
        pass
    return False


def _out_candidates(outfile):
    """List the places where the result file may show up.

    Args:
        outfile: The main output path.

    Returns:
        list: The candidate paths, without duplicates.
    """
    seen = []
    for path in (outfile, HELPER_OUT, HELPER_OUT_EXT, HELPER_OUT_MEDIA):
        if path and path not in seen:
            seen.append(path)
    return seen


def _read_result(outfile):
    """Read the result file written by the helper APK.

    Args:
        outfile: The result file path.

    Returns:
        bytes: The result, or None when there is none yet.

    Raises:
        JVQError: When the content starts with error:.
    """
    if outfile and os.path.isfile(outfile) and os.path.getsize(outfile) > 0:
        try:
            with open(outfile, "rb") as handle:
                data = handle.read()
        except OSError:
            return None
        if data[:6] == b"error:":
            raise JVQError(data.decode("utf-8", "replace").strip())
        return data
    errfile = (outfile + ".err") if outfile else ""
    if errfile and os.path.isfile(errfile):
        try:
            with open(errfile, "rb") as handle:
                text = handle.read().decode("utf-8", "replace")
        except OSError:
            return None
        raise JVQError(text or "err file")
    return None


def _wait_result(outfile, timeout=8.0, interval=0.2):
    """Wait until the helper APK writes the result.

    The helper and the host may live in different mount namespaces, so its
    private cache directory is not always visible; the private path and the
    external storage path are watched at the same time.

    Args:
        outfile: The result file path.
        timeout: Timeout in seconds.
        interval: Poll interval in seconds.

    Returns:
        bytes: The result, or None on timeout.
    """
    candidates = _out_candidates(outfile)
    deadline = time.time() + timeout
    while True:
        for path in candidates:
            result = _read_result(path)
            if result is not None:
                return result
        if time.time() >= deadline:
            return None
        time.sleep(interval)


def _logcat_result(env):
    """Pick the Base64 result the helper APK logged into logcat.

    Args:
        env: The environment for the child process.

    Returns:
        bytes: The result, or None when nothing was found.

    Raises:
        JVQError: When the content starts with error:.
    """
    for cmd in (
        ["/system/bin/logcat", "-d", "-s", "VivoJvq:I"],
        ["/system/bin/logcat", "-d", "-t", "500"],
    ):
        if not os.path.isfile(cmd[0]):
            continue
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env
            )
            raw, _ = proc.communicate(timeout=10)
        except Exception:
            continue
        text = (raw or b"").decode("utf-8", "replace")
        idx = text.rfind("RESULT_B64:")
        if idx < 0:
            continue
        payload = text[idx + len("RESULT_B64:"):].splitlines()[0].strip(" \t\r\n")
        try:
            pad = "=" * (-len(payload) % 4)
            data = base64.b64decode(payload + pad)
        except Exception:
            continue
        if data[:6] == b"error:":
            raise JVQError(data.decode("utf-8", "replace").strip())
        if data:
            return data
    return None


def _clear_logcat(env):
    """Clear logcat so the next result can be picked up.

    Args:
        env: The environment for the child process.
    """
    exe = "/system/bin/logcat"
    if not os.path.isfile(exe):
        return
    try:
        proc = subprocess.Popen(
            [exe, "-c"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env
        )
        proc.communicate(timeout=5)
    except Exception:
        pass


def _android_crypt(op, data):
    """Encrypt or decrypt through the helper APK.

    Args:
        op: encrypt or decrypt.
        data: The input data.

    Returns:
        bytes: The result.

    Raises:
        JVQError: When the helper call fails.
    """
    env = _android_env()
    if not _helper_installed(env):
        raise JVQError("The {} helper APK is not installed".format(HELPER_PACKAGE))
    base = os.path.join(HELPER_CACHE, ".vivosign")
    infile = base + ".in"
    outfile = HELPER_OUT
    for path in (outfile, HELPER_OUT_EXT, HELPER_OUT_MEDIA):
        try:
            os.remove(path)
        except Exception:
            pass
    try:
        os.makedirs(HELPER_CACHE)
    except OSError:
        pass
    with open(infile, "wb") as handle:
        handle.write(data)
    _clear_logcat(env)
    payload = base64.b64encode(data).decode("ascii")
    args = [
        "start", "-W", "--user", "0",
        "-n", "{}/{}".format(HELPER_PACKAGE, HELPER_ACTIVITY),
        "--es", "op", op,
        "--es", "payload", payload,
        "--es", "in", infile,
        "--es", "out", outfile,
    ]
    debug("vivo helper op={} in={} out={} payload={}B".format(op, infile, outfile, len(data)))
    last = None
    for cmd in _am_cmds(args):
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
            raw, err = proc.communicate(timeout=30)
            result = _wait_result(outfile)
            if result is not None:
                return result
            result = _logcat_result(env)
            if result is not None:
                return result
            last = ((raw or b"") + b"\n" + (err or b"")).decode("utf-8", "replace").strip()[:400]
        except JVQError:
            raise
        except Exception as exc:
            last = str(exc)
    raise JVQError(last or "helper apk failed")


def helper_script():
    """Look for the bundled Android vivo JVQ script.

    Returns:
        str: The script path, or an empty string when it is missing.
    """
    env = (os.getenv(SCRIPT_ENV) or "").strip()
    if env:
        return env if os.path.isfile(env) else ""
    here = os.path.dirname(os.path.abspath(__file__))
    roots = [
        here,
        os.path.dirname(here),
        os.path.dirname(os.path.dirname(here)),
        os.getcwd(),
    ]
    for base in roots:
        path = os.path.join(base, SCRIPT_REL)
        if os.path.isfile(path):
            return path
    return ""


def backend_name():
    """Return the name of the backend that would be used.

    Returns:
        str: ``command`` / ``script`` / ``android`` / an empty string.
    """
    if (os.getenv(CRYPT_CMD_ENV) or "").strip():
        return "command"
    if config.is_android():
        if helper_script():
            return "script"
        return "android"
    return ""


def available():
    """Check whether a crypto backend is available.

    Returns:
        bool: True when one is available.
    """
    return bool(backend_name())


def crypt(op, data):
    """Run one JVQ encrypt or decrypt.

    Args:
        op: encrypt or decrypt.
        data: The input data.

    Returns:
        bytes: The result.

    Raises:
        JVQError: When no backend is available or the crypto fails.
    """
    if not isinstance(data, bytes):
        data = str(data).encode("utf-8")
    name = backend_name()
    if name == "command":
        return _command_crypt(op, data)
    if name == "script":
        try:
            return _script_crypt(op, data)
        except JVQError:
            # When the script is unavailable Android can still use the built in helper call.
            if config.is_android():
                return _android_crypt(op, data)
            raise
    if name == "android":
        return _android_crypt(op, data)
    raise JVQError(
        "vivo queries require Android (vivosign helper APK); set {} to an external command".format(
            CRYPT_CMD_ENV
        )
    )
