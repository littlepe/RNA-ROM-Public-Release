# vivo JVQ helper script

Drives the `com.rna.vivosign` helper APK on Android so getrom can encrypt
and decrypt the JVQ packages of the vivo upgrade endpoints.

```
stdin  -> payload
stdout -> result
```

## Requirements

The script checks both of them and exits right away when one is missing:

| Requirement | Message |
| --- | --- |
| running as root | `! this script must run as root (su)` |
| the helper APK is installed | `! the com.rna.vivosign helper APK is not installed` |

Root is needed because the helper writes the result into its own private
cache directory, which a normal app cannot read.

## Build and install the helper APK

The Gradle project lives in `helper-apk/`:

```bash
cd helper-apk
./gradlew assembleDebug
adb install app/build/outputs/apk/debug/app-debug.apk
```

On a rooted device `pm install -r app/build/outputs/apk/debug/app-debug.apk`
works as well.

## Use

```bash
export GETROM_VIVO_CRYPT_CMD="$PWD/tools/vivo_jvq/jvq.sh {op}"
su -c "getrom vivo --device PD2301:V2301A --version V14.0.1.0.TVACNXM --android 14"
```

The script can also be used on its own:

```bash
su -c 'tools/vivo_jvq/jvq.sh encrypt' < payload > cipher
```

## Details

- The payload is passed base64 encoded through the intent extra, the private
  directory of Termux is not readable by the helper.
- The result is read from the private cache of the helper first, then from
  the external storage path, and finally from the `RESULT_B64:` line in
  logcat.
- `VIVO_JVQ_TIMEOUT` sets how long the script waits for the result, 20
  seconds by default.

## The other backends

- `GETROM_VIVO_CRYPT_CMD`: any command of your own, it reads the payload from
  stdin and writes the result to stdout.
- The helper APK started by getrom itself, used when this script is not
  there.
