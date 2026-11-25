# getrom

Query official OTA firmware from the vendor servers: vivo / iQOO, Xiaomi /
Redmi / POCO, Obric, Lenovo, OPPO / OnePlus / Realme (ColorOS) and StepAOS.

The tool runs on Windows, macOS and Linux and needs nothing but Python.
It prints the firmware version, the file name and the download address.

This is the firmware query part of
[RNA-ROM](https://github.com/littlepe/RNA-ROM-Public-Release), split out with
AI so it can be used on a desktop.

**Query only.** There is no device database: no local model files, no model
downloads. Every device attribute comes from the command line.

**English output.** All messages, help texts and errors are in English.

> **Tested on Windows only so far.** The code is written to be portable and
> nothing in it is Windows specific, but the queries were only verified on
> Windows. macOS and Linux should work, give it a try and report what breaks.

## Install

```bash
pip install -e .
```

That is enough for every vendor query. The tracker tools need three extra
packages:

```bash
pip install -r requirements-trackers.txt
```

## Usage

```bash
getrom --help                  # all options
getrom --list                  # the supported vendors
getrom                         # the directories in use
```

### vivo / iQOO

The vendor endpoint exchanges JVQ packages, the crypto needs the vendor
library `libvivoseckey.so`. See [vivo on Android](#vivo-on-android) for the
three ways to provide it.

```bash
getrom vivo --device PD2301:V2301A --version V14.0.1.0.TVACNXM --android 14
getrom vivo --device PD2301:V2301A --version V14.0.1.0.TVACNXM --android 14 --channel BETA
```

The device is given as `codename:software-model`.

### Xiaomi / Redmi / POCO

```bash
getrom xiaomi --device fuxi --version OS1.0.6.0.VOZCNXM --android 15.0 --region CN
```

Sign in to reach the firmware that is not public:

```bash
getrom xiaomi-login --user <account> --type CN
getrom xiaomi-auth-status
getrom xiaomi-auth-clear
```

The password is read from `XIAOMI_PASSWORD` when it is set, so it stays out
of the command line and the process list.

The `AUTO` version needs the two letter device codename of a device
database. There is no device database here, so `AUTO` is not expanded: type
the full version, for example `OS2.0.2.0.VOZCNXM`.

### Obric

```bash
getrom obric --device Pacific --version 1.0.0.0
getrom obric --device Pacific --version 1.0.0.0 --download ./out
```

The query follows the OTA chain, `--download` saves the package and
`--verify` checks its MD5.

### Lenovo

The Lenovo endpoints only accept an SN or an MTM:

```bash
getrom lenovo --sn <device SN>
getrom lenovo --device ZA7T0001CN
```

### OPPO / OnePlus / Realme

```bash
getrom oplus --device PLK110 --branch F
```

Without `--branch` every branch of the model is queried.

### StepAOS / StepX

```bash
getrom stepaos --device PZ261A --version "Step AOS 1.0.0.2.26001_stable_user_20261004_131555"
```

### Tracker tools

The tracker tools of the upstream projects are kept as they are:

```bash
getrom tracker --list
getrom tracker --tool vivo --dtype phone --device PD2301:V2301A --version 16.1.16.5.W10 --android 16 --full 1
getrom tracker --tool tomboy --device PLK110 --branch F --region cn --mode manual
getrom tracker --tool opex --version PJZ110_11.C.84_1840_202601060309 --region cn --info 16,oneplus
```

## vivo on Android

The JVQ crypto needs the vendor library, so on Android the work is done by a
helper APK. There are three ways to wire it up.

**1. The helper script.** `tools/vivo_jvq/jvq.sh` starts the helper APK with
`am start` and reads the result back. It needs root, and the helper APK has
to be installed already:

```bash
export GETROM_VIVO_CRYPT_CMD="$PWD/tools/vivo_jvq/jvq.sh {op}"
su -c "getrom vivo --device PD2301:V2301A --version V14.0.1.0.TVACNXM --android 14"
```

**2. The helper APK.** `helper-apk/` holds the Gradle project of the
`com.rna.vivosign` application. Build and install it once:

```bash
cd helper-apk
./gradlew assembleDebug
adb install app/build/outputs/apk/debug/app-debug.apk
```

getrom falls back to starting that APK on its own when the script is not
there.

**3. An external command.** Any command that reads the payload from stdin and
writes the result to stdout works, `{op}` is replaced by `encrypt` or
`decrypt`:

```bash
export GETROM_VIVO_CRYPT_CMD="python my_jvq_helper.py {op}"
```

Without any of them the vivo query stops with a message, the other vendors
are not affected.

## Directories

| Platform | Config (switches, credentials) | Data (cache, downloads) |
| --- | --- | --- |
| Windows | `%APPDATA%\getrom` | `%LOCALAPPDATA%\getrom` |
| macOS | `~/Library/Application Support/getrom` | `~/Library/Application Support/getrom/data` |
| Linux | `$XDG_CONFIG_HOME/getrom` or `~/.config/getrom` | `$XDG_DATA_HOME/getrom` or `~/.local/share/getrom` |
| Android | `$START_DIR` | `$START_DIR/runtime/database` |

| Variable | Meaning |
| --- | --- |
| `GETROM_CONFIG_DIR` | Config directory |
| `GETROM_DATA_DIR` | Data directory |
| `GETROM_HOME` | Both of them (`config/`, `data/`) |
| `START_DIR` / `START` | Settings directory on Android |
| `GETROM_DEBUG` | Debug log switch |
| `XIAOMI_PASSWORD` | Xiaomi account password |
| `GETROM_VIVO_CRYPT_CMD` | External command for the vivo JVQ crypto |
| `VIVO_JVQ_SCRIPT` | Path to the Android JVQ script |

`getrom info` prints the directories that are actually in use.

## Layout

```
src/getrom/
├── cli.py          command line entry
├── config.py       directories and settings
├── crypto.py       pure Python AES and RSA-OAEP
├── jvq.py          vivo JVQ crypto backends
├── log.py          output and debug logs
├── net.py          HTTP and downloads
├── trackers/       tracker bridge and the ported trackers
├── vendors/        the vendor queries
└── licenses/       license texts of the vendored code

helper-apk/         the com.rna.vivosign helper APK for Android
tools/vivo_jvq/     shell script that drives the helper APK
```

## Third party code

The tracker code comes from three projects and keeps its own license. The
full texts are in `src/getrom/licenses/`, the details in
`THIRD_PARTY_LICENSES.md`.

| Project | Path | License |
| --- | --- | --- |
| [OPlus-Tracker](https://github.com/JerryTse-OSS/OPlus-Tracker) by Jerry Tse | `src/getrom/trackers/oplus/` | LGPL-3.0-or-later |
| [VIVO-OTA-Tracker](https://github.com/JerryTse-OSS/VIVO-OTA-Tracker) | `src/getrom/trackers/vivo.py` | Apache-2.0 |
| [VIVO-OTA-Tracker-Android](https://github.com/mytiantian001/VIVO-OTA-Tracker-Android) | reference for the JVQ crypto | Apache-2.0 |

The helper APK in `helper-apk/` is the VivoSign helper, MIT licensed. The
vendor library `libvivoseckey.so` is not redistributed, it is extracted from
the stock vivo updater.

getrom itself is MIT licensed, see `LICENSE`.

## Development

```bash
pip install -e ".[trackers]" pytest
pytest
```

The tests run offline.
