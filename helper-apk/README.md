# VivoSign helper APK

Small Android helper that does the vivo JVQ encryption and decryption with the
vendor library `libvivoseckey.so`.

`getrom vivo` talks to the vivo upgrade servers, and those requests and
answers are JVQ packages. The crypto lives in a closed source library, so a
device side helper is the practical way to run it.

## How it works

1. `VivoJvqActivity` loads `libvivoseckey.so` and initialises it with a
   spoofed vivo context, which is what the signature check looks at.
2. The activity encrypts or decrypts the payload and writes the result to a
   file. The intent can also carry the payload directly.

The activity is exported and listens for the action
`com.rna.tools.VIVO_JVQ`, so it can be started with `am start` from a shell.

## Build

```bash
./gradlew assembleDebug
```

The APK lands in `app/build/outputs/apk/debug/app-debug.apk`.

## Install

```bash
adb install app/build/outputs/apk/debug/app-debug.apk
```

On a rooted device the package can also be installed with
`pm install -r`.

## Requirements

- Android 5.0 or newer (API 21)
- an arm64 device, `libvivoseckey.so` is arm64-v8a only

## Use with getrom

`tools/vivo_jvq/jvq.sh` drives this APK and is what `getrom` calls on
Android:

```bash
export GETROM_VIVO_CRYPT_CMD="$PWD/tools/vivo_jvq/jvq.sh {op}"
getrom vivo --device PD2301:V2301A --version V14.0.1.0.TVACNXM --android 14
```

The script needs root, because it reads the result from the private cache
directory of the helper.

## Credits

- `libvivoseckey.so` extracted from the stock vivo `com.bbk.updater`
- the JNI bridge follows
  [VIVO-OTA-Tracker-Android](https://github.com/mytiantian001/VIVO-OTA-Tracker-Android)

## License

MIT, see `LICENSE`.
