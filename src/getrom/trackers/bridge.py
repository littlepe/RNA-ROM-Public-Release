# -*- coding: utf-8 -*-
"""The tracker bridge.

The ported VIVO-OTA-Tracker and OPlus-Tracker are exposed through one
entry point, ``getrom tracker --tool <name>``. The original projects stay
separate and untouched; this module only assembles the arguments and
forwards the call.

The trackers need ``requests`` / ``cryptography`` / ``remotezip``; when they
are missing only the matching tool complains, the other queries are not
affected.
"""

from __future__ import print_function

import importlib
import shlex
import sys
import traceback
import warnings

from ..log import err, out, phase

# The trackers need cryptography, which warns when the OpenSSL legacy provider
# is missing; every algorithm used here lives in the default provider, so the
# warning is muted.
warnings.filterwarnings("ignore", message=r".*legacy provider failed to load.*")

# tool -> (module name, description)
TOOLS = {
    "vivo": ("getrom.trackers.vivo", "Vivo / iQOO OTA query (VIVO-OTA-Tracker)"),
    "tomboy": ("getrom.trackers.oplus.tomboy_pro", "Main OTA query for OPPO / OnePlus / Realme"),
    "opex": ("getrom.trackers.oplus.opex_query", "OPEX query"),
    "opex-analyzer": ("getrom.trackers.oplus.opex_analyzer", "OPEX analysis"),
    "sota": ("getrom.trackers.oplus.sota_query", "SOTA (system module APK) query"),
    "sota-changelog": ("getrom.trackers.oplus.sota_changelog_query", "SOTA changelog"),
    "iot": ("getrom.trackers.oplus.iot_query", "IOT query against the legacy server"),
    "iot-new": ("getrom.trackers.oplus.iot_query_new", "IOT query against the new server"),
    "iot-changelog": ("getrom.trackers.oplus.iot_changelog_query", "IOT changelog"),
    "downgrade": ("getrom.trackers.oplus.downgrade_query", "Official downgrade package query"),
    "downgrade-old": ("getrom.trackers.oplus.downgrade_query_old",
                      "Official downgrade package query (legacy)"),
    "realme-edl": ("getrom.trackers.oplus.realme_edl_query", "Realme EDL package query"),
    "changelog": ("getrom.trackers.oplus.changelog_query", "Changelog of a given version"),
    "desc": ("getrom.trackers.oplus.desc_query", "Description link of a given version"),
    "c16": ("getrom.trackers.oplus.transfer", "ColorOS 16 direct link resolution"),
    "earbuds": ("getrom.trackers.oplus.earbuds_query", "OPPO / OnePlus earbuds firmware query"),
}


def list_tools():
    """List the available tracker tools.

    Returns:
        list: The tool names.
    """
    return list(TOOLS.keys())


def _import(module_name):
    """Import a module by name, None when it fails.

    Args:
        module_name: The module name.

    Returns:
        module: The module object, None when the import failed.
    """
    try:
        return importlib.import_module(module_name)
    except ImportError as exc:
        err("> Failed to import {}: {} (missing dependency? pip install getrom[trackers])".format(
            module_name, exc))
        return None
    except Exception as exc:
        err("> Failed to import {}: {}".format(module_name, exc))
        return None


def _opt(obj, name, default=None):
    """Read an attribute of the arguments without raising.

    Args:
        obj: The argument object.
        name: The attribute name.
        default: The default value.

    Returns:
        object: The attribute value.
    """
    value = getattr(obj, name, default)
    if value is None:
        return default
    return value


def _text(obj, name, default=""):
    """Read a string argument and strip it.

    Args:
        obj: The argument object.
        name: The attribute name.
        default: The default value.

    Returns:
        str: The argument text.
    """
    value = _opt(obj, name, default)
    return str(value).strip() if value is not None else default


def _region(obj, default="cn"):
    """Normalise a region code to lower case.

    Args:
        obj: The argument object.
        default: The default region.

    Returns:
        str: The region code.
    """
    return (_text(obj, "region", default) or default).lower()


def _full_on(obj):
    """Check whether a full package is wanted.

    Args:
        obj: The argument object.

    Returns:
        bool: True for a full package.
    """
    value = _text(obj, "full", "1").lower()
    return value not in ("0", "false", "off", "no", "")


def _run_main(module, argv):
    """Call the main() of a module with the given argv and catch SystemExit.

    Args:
        module: The module object.
        argv: The argument list.

    Returns:
        int: The exit code, 0 on success.
    """
    main = getattr(module, "main", None)
    if main is None:
        out("> {} has no main entry".format(getattr(module, "__name__", "?")))
        return 1
    old_argv = sys.argv
    sys.argv = [getattr(module, "__name__", "tool")] + list(argv)
    try:
        rc = main()
    except SystemExit as exc:
        code = exc.code
        if code is None or code == "":
            return 0
        return code if isinstance(code, int) else 1
    finally:
        sys.argv = old_argv
    if rc is None:
        return 0
    return rc if isinstance(rc, int) else 0


def run_tracker(tool, args):
    """Run one tracker tool.

    Args:
        tool: The tool name from TOOLS.
        args: The argument object with --tool, --args and the vendor fields.

    Returns:
        int: The exit code, 0 on success.
    """
    name = (tool or "").strip().lower()
    raw_args = _text(args, "args", "")
    phase("Tracker: {}".format(name or "?"))

    # Raw arguments win, they can override any option that has no structure.
    if raw_args and name in TOOLS:
        module = _import(TOOLS[name][0])
        if module is None:
            return 1
        try:
            argv = shlex.split(raw_args)
        except Exception:
            argv = raw_args.split()
        try:
            return _run_main(module, argv) if hasattr(module, "main") else _run_special(name, args)
        except Exception:
            err(traceback.format_exc())
            return 1

    handler = {
        "vivo": _vivo,
        "tomboy": _tomboy,
        "opex": _opex,
        "opex-analyzer": _opex_analyzer,
        "sota": _sota,
        "sota-changelog": _sota_changelog,
        "iot": _iot,
        "iot-new": _iot_new,
        "iot-changelog": _iot_changelog,
        "downgrade": _downgrade,
        "downgrade-old": _downgrade_old,
        "realme-edl": _realme_edl,
        "changelog": _changelog,
        "desc": _desc,
        "c16": _c16,
        "earbuds": _earbuds,
    }.get(name)

    if handler is None:
        out("> Unknown tracker tool: {}".format(name or "(empty)"))
        out("> Available: {}".format(", ".join(list_tools())))
        return 2

    try:
        return handler(args) or 0
    except SystemExit as exc:
        code = exc.code
        return code if isinstance(code, int) else 0
    except Exception:
        err(traceback.format_exc())
        return 1


# ---------------------------------------------------------------------------
# Argument assembly per tool
# ---------------------------------------------------------------------------


def _vivo(args):
    """Vivo / iQOO OTA query (VIVO-OTA-Tracker).

    Args:
        args: The argument object.

    Returns:
        int: The exit code.
    """
    module = _import(TOOLS["vivo"][0])
    if module is None:
        return 1
    dtype = (_text(args, "dtype", "") or "phone").lower()
    if dtype not in ("phone", "tablet"):
        dtype = "phone"
    raw = _text(args, "device", "")
    if ":" in raw:
        sw, dm = raw.split(":", 1)
    else:
        sw, dm = raw, raw
    model_sw = _text(args, "sw", "") or _text(args, "model", "") or sw
    device_model = _text(args, "codename", "") or dm or raw
    android = _text(args, "android", "")
    try:
        android_ver = int(float(android)) if android else 0
    except Exception:
        android_ver = 0
    config = module.DeviceConfig(
        device_type=dtype,
        model_sw_ver=model_sw,
        device_model=device_model,
        sw_version=_text(args, "version", ""),
        android_ver=android_ver,
        snp=_text(args, "sn", "") or "A0000000000000A",
        is_full=_full_on(args),
        verbose=bool(_opt(args, "debug", False)),
    )
    info = module.query_ota_update(config)
    return 0 if info else 1


def _ota_prefix(args):
    """Build the OTA version prefix: --version first, then model_branch.

    Args:
        args: The argument object.

    Returns:
        str: The version prefix.
    """
    version = _text(args, "version", "")
    if version:
        return version
    device = _text(args, "device", "") or _text(args, "model", "")
    branch = _text(args, "branch", "")
    if device and branch:
        return "{}_{}".format(device, branch)
    return device


def _tomboy(args):
    """Main OTA query for OPPO / OnePlus / Realme.

    Args:
        args: The argument object.

    Returns:
        int: The exit code.
    """
    module = _import(TOOLS["tomboy"][0])
    if module is None:
        return 1
    region = _region(args, "cn")
    argv = [_ota_prefix(args), region]
    model = _text(args, "model", "") or _text(args, "device", "")
    if model:
        argv += ["--model", model]
    mode = _text(args, "mode", "")
    if mode:
        argv += ["--mode", mode]
    if _text(args, "genshin", ""):
        argv += ["--genshin", _text(args, "genshin", "0")]
    if _text(args, "pre", ""):
        argv += ["--pre", _text(args, "pre", "0")]
    guid = _text(args, "guid", "")
    if guid:
        argv += ["--guid", guid]
    components = _text(args, "components", "")
    if components:
        argv += ["--components", components]
    if _text(args, "anti", ""):
        argv += ["--anti", _text(args, "anti", "0")]
    nvid = _text(args, "nvid", "")
    if nvid:
        argv += ["--nvid", nvid]
    if _text(args, "recruit", ""):
        argv += ["--recruit", _text(args, "recruit", "0")]
    if _text(args, "original_link", ""):
        argv += ["--original-link", _text(args, "original_link", "0")]
    if _text(args, "pki", ""):
        argv += ["--pki", _text(args, "pki", "0")]
    return _run_main(module, argv)


def _opex(args):
    """OPEX query.

    Args:
        args: The argument object.

    Returns:
        int: The exit code.
    """
    module = _import(TOOLS["opex"][0])
    if module is None:
        return 1
    argv = [_ota_prefix(args), _region(args, "cn"), "--info", _text(args, "info", "")]
    return _run_main(module, argv)


def _opex_analyzer(args):
    """OPEX analysis.

    Args:
        args: The argument object.

    Returns:
        int: The exit code.
    """
    module = _import(TOOLS["opex-analyzer"][0])
    if module is None:
        return 1
    return _run_main(module, [_text(args, "url", "")])


def _sota(args):
    """SOTA query (the module has no main, the core function is called directly).

    Args:
        args: The argument object.

    Returns:
        int: The exit code.
    """
    module = _import(TOOLS["sota"][0])
    if module is None:
        return 1
    result = module.run_sota_query(
        _ota_prefix(args), _region(args, "cn"), _text(args, "brand", ""), _text(args, "coloros", "")
    )
    printer = getattr(module, "print_formatted_output", None)
    if printer is not None:
        printer(result.get("sota_version", ""), result.get("formatted_lines", []))
    else:
        for line in result.get("formatted_lines", []):
            out(line)
    return 0


def _sota_changelog(args):
    """SOTA changelog (the module has no main, the core function is called directly).

    Args:
        args: The argument object.

    Returns:
        int: The exit code.
    """
    module = _import(TOOLS["sota-changelog"][0])
    if module is None:
        return 1
    result = module.run_sota_changelog_query(
        _ota_prefix(args), _region(args, "cn"), _text(args, "brand", ""), _text(args, "coloros", "")
    )
    for line in result.get("output_lines", []):
        out(line)
    return 0


def _iot(args):
    """IOT query against the legacy server.

    Args:
        args: The argument object.

    Returns:
        int: The exit code.
    """
    module = _import(TOOLS["iot"][0])
    if module is None:
        return 1
    argv = [_ota_prefix(args), _region(args, "cn")]
    model = _text(args, "model", "")
    if model:
        argv += ["--model", model]
    return _run_main(module, argv)


def _iot_new(args):
    """IOT query against the new server.

    Args:
        args: The argument object.

    Returns:
        int: The exit code.
    """
    module = _import(TOOLS["iot-new"][0])
    if module is None:
        return 1
    argv = [_ota_prefix(args), _text(args, "hardware", ""), _region(args, "cn")]
    return _run_main(module, argv)


def _iot_changelog(args):
    """IOT changelog.

    Args:
        args: The argument object.

    Returns:
        int: The exit code.
    """
    module = _import(TOOLS["iot-changelog"][0])
    if module is None:
        return 1
    argv = [_ota_prefix(args), _region(args, "cn")]
    model = _text(args, "model", "")
    if model:
        argv += ["--model", model]
    return _run_main(module, argv)


def _downgrade(args):
    """Official downgrade package query.

    Args:
        args: The argument object.

    Returns:
        int: The exit code.
    """
    module = _import(TOOLS["downgrade"][0])
    if module is None:
        return 1
    argv = [
        _ota_prefix(args),
        _text(args, "prj", ""),
        _text(args, "sn", ""),
        _text(args, "duid", ""),
    ]
    if _text(args, "cmcc", ""):
        argv += ["--cmcc", _text(args, "cmcc", "0")]
    if _opt(args, "debug", False):
        argv += ["--debug", "1"]
    return _run_main(module, argv)


def _downgrade_old(args):
    """Official downgrade package query (legacy).

    Args:
        args: The argument object.

    Returns:
        int: The exit code.
    """
    module = _import(TOOLS["downgrade-old"][0])
    if module is None:
        return 1
    argv = [_ota_prefix(args), _text(args, "prj", "")]
    if _text(args, "cmcc", ""):
        argv += ["--cmcc", _text(args, "cmcc", "0")]
    return _run_main(module, argv)


def _realme_edl(args):
    """Realme EDL package query.

    Args:
        args: The argument object.

    Returns:
        int: The exit code.
    """
    module = _import(TOOLS["realme-edl"][0])
    if module is None:
        return 1
    argv = [_text(args, "version", ""), _text(args, "region", "CN"), _text(args, "date", "")]
    return _run_main(module, argv)


def _changelog(args):
    """Changelog of a given version.

    Args:
        args: The argument object.

    Returns:
        int: The exit code.
    """
    module = _import(TOOLS["changelog"][0])
    if module is None:
        return 1
    argv = [_ota_prefix(args), _region(args, "cn")]
    if _text(args, "pre", ""):
        argv += ["--pre", _text(args, "pre", "0")]
    return _run_main(module, argv)


def _desc(args):
    """Description link of a given version.

    Args:
        args: The argument object.

    Returns:
        int: The exit code.
    """
    module = _import(TOOLS["desc"][0])
    if module is None:
        return 1
    argv = [_ota_prefix(args), _region(args, "cn")]
    return _run_main(module, argv)


def _c16(args):
    """ColorOS 16 direct link resolution (the core function is called directly).

    Args:
        args: The argument object.

    Returns:
        int: The exit code.
    """
    module = _import(TOOLS["c16"][0])
    if module is None:
        return 1
    url = _text(args, "url", "")
    if not url:
        out("> URL cannot be empty")
        return 1
    result = module.get_redirect_url(url)
    if result:
        out("✅ Resolved")
        return 0
    out("❌ Parsing failed")
    return 1


def _earbuds(args):
    """OPPO / OnePlus earbuds firmware query.

    Args:
        args: The argument object.

    Returns:
        int: The exit code.
    """
    module = _import(TOOLS["earbuds"][0])
    if module is None:
        return 1
    action = _text(args, "prodid", "") or "get"
    argv = [action, (_text(args, "region", "cn") or "cn").lower()]
    return _run_main(module, argv)


def _run_special(name, args):
    """Dispatch for the modules without a main when raw --args are used.

    Args:
        name: The tool name.
        args: The argument object.

    Returns:
        int: The exit code.
    """
    if name == "sota":
        return _sota(args)
    if name == "sota-changelog":
        return _sota_changelog(args)
    if name == "c16":
        return _c16(args)
    out("> {} does not support raw --args".format(name))
    return 1
