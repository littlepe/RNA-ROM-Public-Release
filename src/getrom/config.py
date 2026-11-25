# -*- coding: utf-8 -*-
"""Cross platform paths and settings.

The standalone getrom no longer assumes it runs on Android/Termux: the config
and data directories follow the conventions of each platform (Windows /
macOS / Linux). The ``START_DIR`` environment variable of the RNA project is
still honoured, so the same settings work on Android and on the desktop.

Directory layout:

* Config directory: switches and credentials (``.getrom_mirror``,
  ``.getrom_xiaomi_auth``, ...).
* Data directory: query caches and downloaded files.
"""

from __future__ import print_function

import os
import sys

APP_NAME = "getrom"


def is_windows():
    """Check whether the current platform is Windows.

    Returns:
        bool: True on Windows.
    """
    return os.name == "nt" or sys.platform.startswith("win")


def is_macos():
    """Check whether the current platform is macOS.

    Returns:
        bool: True on macOS.
    """
    return sys.platform == "darwin"


def is_android():
    """Check whether the current platform is Android.

    Returns:
        bool: True on Android.
    """
    if os.environ.get("ANDROID_ROOT") or os.environ.get("ANDROID_DATA"):
        return True
    if "ANDROID_STORAGE" in os.environ:
        return True
    return os.path.isdir("/system/app") and os.path.isdir("/system/framework")


def platform_name():
    """Return the platform identifier.

    Returns:
        str: ``windows`` / ``macos`` / ``android`` / ``linux`` / ``other``.
    """
    if is_android():
        return "android"
    if is_windows():
        return "windows"
    if is_macos():
        return "macos"
    if sys.platform.startswith("linux"):
        return "linux"
    return "other"


def _env(*names):
    """Return the first non empty environment variable.

    Args:
        names: Environment variable names.

    Returns:
        str: The value, or an empty string when all of them are unset.
    """
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return ""


def _expand(path):
    """Expand ``~`` and environment variables in a path.

    Args:
        path: The raw path.

    Returns:
        str: The expanded absolute path.
    """
    if not path:
        return ""
    return os.path.abspath(os.path.expanduser(os.path.expandvars(path)))


def _mkdir(path):
    """Create a directory, ignoring an existing one.

    Args:
        path: Directory path.

    Returns:
        str: The directory path.
    """
    if path and not os.path.isdir(path):
        try:
            os.makedirs(path)
        except OSError:
            pass
    return path


def home_dir():
    """Return the user home directory.

    Returns:
        str: The home directory path.
    """
    return os.path.expanduser("~")


def config_dir():
    """Return the config directory, where the switches and credentials live.

    Priority: ``GETROM_CONFIG_DIR`` > ``GETROM_HOME`` > ``START_DIR`` (Android)
    > the platform default.

    Returns:
        str: The config directory path.
    """
    env = _env("GETROM_CONFIG_DIR")
    if env:
        return _expand(env)
    home = _env("GETROM_HOME")
    if home:
        return _expand(os.path.join(home, "config"))
    legacy = _env("START_DIR", "START")
    if legacy and is_android():
        return _expand(legacy)
    if is_windows():
        base = _env("APPDATA") or os.path.join(home_dir(), "AppData", "Roaming")
        return _expand(os.path.join(base, APP_NAME))
    if is_macos():
        return _expand(os.path.join(home_dir(), "Library", "Application Support", APP_NAME))
    base = _env("XDG_CONFIG_HOME") or os.path.join(home_dir(), ".config")
    return _expand(os.path.join(base, APP_NAME))


def data_dir():
    """Return the data directory, where the caches and downloads live.

    Priority: ``GETROM_DATA_DIR`` > ``GETROM_HOME`` > ``START_DIR`` (Android)
    > the platform default.

    Returns:
        str: The data directory path.
    """
    env = _env("GETROM_DATA_DIR")
    if env:
        return _expand(env)
    home = _env("GETROM_HOME")
    if home:
        return _expand(os.path.join(home, "data"))
    legacy = _env("START_DIR", "START")
    if legacy and is_android():
        return _expand(os.path.join(legacy, "runtime", "database"))
    if is_windows():
        base = _env("LOCALAPPDATA") or os.path.join(home_dir(), "AppData", "Local")
        return _expand(os.path.join(base, APP_NAME))
    if is_macos():
        return _expand(os.path.join(home_dir(), "Library", "Application Support", APP_NAME, "data"))
    base = _env("XDG_DATA_HOME") or os.path.join(home_dir(), ".local", "share")
    return _expand(os.path.join(base, APP_NAME))


def settings_dir():
    """Return the directory holding the setting files.

    Android keeps using ``START_DIR``; the desktop uses the config directory.

    Returns:
        str: The settings directory path.
    """
    legacy = _env("START_DIR", "START")
    if legacy:
        return _expand(legacy)
    return config_dir()


def ensure_dir(path):
    """Make sure a directory exists.

    Args:
        path: Directory path.

    Returns:
        str: The directory path.
    """
    return _mkdir(path)


def read_text(path):
    """Read a text file.

    Args:
        path: File path.

    Returns:
        str: The file text, or an empty string when it cannot be read.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except (OSError, TypeError, ValueError):
        try:
            with open(path, "r") as handle:
                return handle.read()
        except OSError:
            return ""


def write_text(path, text):
    """Write a text file.

    Args:
        path: File path.
        text: File content.

    Returns:
        bool: True when the file was written.
    """
    folder = os.path.dirname(path)
    if folder:
        _mkdir(folder)
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        return True
    except OSError:
        return False


def read_setting(name):
    """Read the first line of a setting file.

    Args:
        name: Setting file name.

    Returns:
        str: The first line, or an empty string when the file is missing.
    """
    path = os.path.join(settings_dir(), name)
    if not os.path.isfile(path):
        return ""
    text = read_text(path).strip()
    if not text:
        return ""
    return text.splitlines()[0].strip()


def write_setting(name, text):
    """Write a setting file.

    Args:
        name: Setting file name.
        text: File content.

    Returns:
        bool: True when the file was written.
    """
    return write_text(os.path.join(settings_dir(), name), str(text).strip() + "\n")


def remove_setting(name):
    """Delete a setting file.

    Args:
        name: Setting file name.

    Returns:
        bool: True when the file was removed.
    """
    path = os.path.join(settings_dir(), name)
    try:
        os.remove(path)
        return True
    except OSError:
        return False
