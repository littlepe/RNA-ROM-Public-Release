# Third party licenses

getrom ships third party code. The list below covers everything that is
vendored into this repository, with the license each project uses and where
the copy lives.

The license texts are kept verbatim in `src/getrom/licenses/` (shipped with
the package) and in `licenses/` of the repository.

## Summary

| Component | Path in this repository | License | Upstream |
| --- | --- | --- | --- |
| OPlus-Tracker | `src/getrom/trackers/oplus/` | LGPL-3.0-or-later | https://github.com/JerryTse-OSS/OPlus-Tracker |
| VIVO-OTA-Tracker | `src/getrom/trackers/vivo.py` | Apache-2.0 | https://github.com/JerryTse-OSS/VIVO-OTA-Tracker |
| VIVO-OTA-Tracker-Android | `src/getrom/trackers/vivo.py` (JNI bridge ideas) | Apache-2.0 | https://github.com/mytiantian001/VIVO-OTA-Tracker-Android |
| VivoSign helper APK | `helper-apk/` | MIT | this repository, see `helper-apk/LICENSE` |

## OPlus-Tracker

Author: Jerry Tse. Licensed under the GNU Lesser General Public License,
version 3 or (at your option) any later version. The full text is in
`src/getrom/licenses/OPlus-Tracker/LICENSE` (LGPL-3.0 followed by the
GPL-3.0 text it incorporates).

The files under `src/getrom/trackers/oplus/` are derived from that project.
They were re-indented to the style of this repository and the Chinese output
text was translated into English; no functional change was made.

Because the vendored part is a library used by an application, the LGPL
terms apply to that directory: you may use it under the LGPL, or link
against it under the GPL. `src/getrom/trackers/bridge.py` is the only file
that talks to it, and it is a separate module.

## VIVO-OTA-Tracker

Licensed under the Apache License, version 2.0. The full text is in
`src/getrom/licenses/VIVO-OTA-Tracker/LICENSE`.

`src/getrom/trackers/vivo.py` is derived from that project. The output text
was translated into English and the module was moved into the
`getrom.trackers` package; the crypto, the request building and the
response parsing are unchanged.

## VIVO-OTA-Tracker-Android

Licensed under the Apache License, version 2.0. The full text is in
`src/getrom/licenses/VIVO-OTA-Tracker-Android/LICENSE`.

That project is the Android app that loads `libvivoseckey.so`. The JNI
bridge and the key handling it documents are the reference for the JVQ
crypto used by `src/getrom/jvq.py` and by the helper script in
`tools/vivo_jvq/`. No source code is copied from it into this repository
beyond the ideas described in those two files.

## libvivoseckey.so

The vendor library `libvivoseckey.so` is **not** redistributed here. It is
extracted from the stock vivo updater by the upstream projects and has to be
supplied by the user:

* `tools/vivo_jvq/` calls the library that is already on the device or that
  the user copied from the `RNA-ROM-VivoSign-Helper` project;
* the helper APK (`com.rna.vivosign`) is built from `helper-apk/` in this
  repository and is not part of the Python package either.

## The helper APK

`helper-apk/` is the Gradle project of the `com.rna.vivosign` helper, MIT
licensed, see `helper-apk/LICENSE`. It carries the same idea as
VIVO-OTA-Tracker-Android: the vendor library is initialised with a spoofed
context and the payload is handed over through an intent.

## Licenses of this project

The code of getrom itself is under the MIT license, see `LICENSE`.
