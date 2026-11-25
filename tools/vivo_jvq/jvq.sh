#!/system/bin/sh

# ---- vivo JVQ crypto (Android, root) ----------------------------------------
# Call the com.rna.vivosign helper APK to encrypt / decrypt JVQ data with the
# vendor JNI (libvivoseckey.so).
#
#   stdin  -> payload
#   stdout -> result
#
# Usage: su -c 'jvq.sh <encrypt|decrypt>' < payload > result
#
# Requirements (checked below, the script exits when they are not met):
#   * the script must run as root (su)
#   * the com.rna.vivosign helper APK must be installed
#
# Build and install the helper APK from the helper-apk directory:
#   cd helper-apk && ./gradlew assembleDebug
#   adb install app/build/outputs/apk/debug/app-debug.apk
#
# The script never installs anything.

PKG="com.rna.vivosign"
ACT="com.rna.tools.VivoJvqActivity"
ACTION="com.rna.tools.VIVO_JVQ"
PRIV_OUT="/data/user/0/${PKG}/cache/.vivosign.out"
EXT_OUT="/storage/emulated/0/Android/data/${PKG}/files/.vivosign.out"
TIMEOUT="${VIVO_JVQ_TIMEOUT:-20}"

err() {
    printf '%s\n' "! $*" >&2
}

# base64 one line: prefer toybox base64, fall back to openssl.
b64_encode() {
    if command -v base64 > /dev/null 2>&1; then
        base64 | tr -d '\r\n'
    elif command -v openssl > /dev/null 2>&1; then
        openssl base64 -A
    else
        cat
    fi
}

# base64 decode one line.
b64_decode() {
    if command -v base64 > /dev/null 2>&1; then
        base64 -d
    elif command -v openssl > /dev/null 2>&1; then
        openssl base64 -d -A
    else
        cat
    fi
}

# Read the result written by the helper APK.
read_result() {
    for path in "${PRIV_OUT}" "${EXT_OUT}"; do
        if [ -f "$path" ] && [ -s "$path" ]; then
            cat "$path"
            return 0
        fi
    done
    # Fall back to logcat: the helper logs RESULT_B64:<base64>.
    line="$(logcat -d -s VivoJvq:I 2> /dev/null | grep 'RESULT_B64:' | tail -n 1)"
    if [ -n "$line" ]; then
        printf '%s' "$line" | sed 's/.*RESULT_B64://' | tr -d '\r\n' | b64_decode
        return 0
    fi
    return 1
}

OP="${1:-}"
case "$OP" in
    encrypt | decrypt) ;;
    *)
        err "usage: jvq.sh <encrypt|decrypt>"
        exit 2
        ;;
esac

# Must run as root: the helper writes into its own private cache directory.
if [ "$(id -u)" != "0" ]; then
    err "this script must run as root (su)"
    exit 1
fi

# The helper APK must already be installed.
if ! pm path "${PKG}" 2> /dev/null | grep -q "package:"; then
    err "the ${PKG} helper APK is not installed"
    exit 1
fi

PAYLOAD="$(b64_encode)"
if [ -z "$PAYLOAD" ]; then
    err "no input data"
    exit 1
fi

rm -f "${PRIV_OUT}" "${EXT_OUT}" 2> /dev/null

am start -W --user 0 \
    -n "${PKG}/${ACT}" \
    -a "${ACTION}" \
    --es op "${OP}" \
    --es payload "${PAYLOAD}" \
    --es out "${PRIV_OUT}" > /dev/null 2>&1

TMP_OUT="${TMPDIR:-/tmp}/.vivosign.$$"
deadline=$(( $(date +%s) + TIMEOUT ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    if read_result > "$TMP_OUT" 2> /dev/null && [ -s "$TMP_OUT" ]; then
        cat "$TMP_OUT"
        rm -f "$TMP_OUT"
        exit 0
    fi
    rm -f "$TMP_OUT"
    sleep 0.2
done

# Last chance: the helper may have written an error message.
if [ -f "${PRIV_OUT}" ] && [ -s "${PRIV_OUT}" ]; then
    cat "${PRIV_OUT}"
    exit 0
fi

err "the helper APK returned no result"
exit 1
