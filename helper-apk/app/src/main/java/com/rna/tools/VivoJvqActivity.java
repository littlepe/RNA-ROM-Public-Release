package com.rna.tools;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;

import com.rna.vivosign.crypto.FakeVivoContext;
import com.vivo.seckeysdk.utils.NativeRequest;
import com.vivo.seckeysdk.utils.NativeResponse;
import com.vivo.seckeysdk.utils.SDKCipherNative;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

public class VivoJvqActivity extends Activity {

    private static final String TAG = "VivoJvq";
    private static final String TARGET_PACKAGE = "com.bbk.updater";
    private static boolean nativeInitialized = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Intent intent = getIntent();
        String op = intent.getStringExtra("op");
        String payload = intent.getStringExtra("payload");
        String infile = intent.getStringExtra("in");
        String outfile = intent.getStringExtra("out");

        File cacheOut = new File(getCacheDir(), ".vivosign.out");
        Log.i(TAG, "start op=" + op + " out=" + outfile
                + " cacheDir=" + getCacheDir() + " cacheOut=" + cacheOut);

        try {
            byte[] data = resolveInputData(payload, infile);
            if (data == null || data.length == 0) {
                writeResult("error: no input data".getBytes(), outfile, cacheOut);
                finish();
                return;
            }
            Log.i(TAG, "input bytes=" + data.length);

            ensureNativeInit();

            byte[] result;
            if ("encrypt".equalsIgnoreCase(op)) {
                result = nativeEncrypt(data);
            } else if ("decrypt".equalsIgnoreCase(op)) {
                result = nativeDecrypt(data);
            } else {
                writeResult(("error: unknown op=" + op).getBytes(), outfile, cacheOut);
                finish();
                return;
            }
            Log.i(TAG, "result bytes=" + (result == null ? -1 : result.length));

            if (result != null) {
                writeResult(result, outfile, cacheOut);
            } else {
                writeResult("error: crypto returned null".getBytes(), outfile, cacheOut);
            }
        } catch (Throwable e) {
            Log.e(TAG, "Error", e);
            try {
                writeResult(("error: " + e.getMessage()).getBytes("UTF-8"), outfile, cacheOut);
            } catch (Exception ex) {
                Log.e(TAG, "error write failed", ex);
            }
        }

        finish();
    }

    private void writeResult(byte[] result, String outfile, File cacheOut) {
        Log.i(TAG, "RESULT_B64:" + Base64.encodeToString(result, Base64.NO_WRAP));
        writeFile(cacheOut.getAbsolutePath(), result);
        writeFile(outfile, result);
        try {
            File ext = getExternalFilesDir(null);
            if (ext != null) {
                writeFile(new File(ext, ".vivosign.out").getAbsolutePath(), result);
            }
        } catch (Throwable e) {
            Log.e(TAG, "external write failed", e);
        }
    }

    private byte[] resolveInputData(String payload, String infile) {
        if (payload != null && !payload.isEmpty()) {
            try {
                return Base64.decode(payload, Base64.DEFAULT);
            } catch (Exception e) {
                Log.e(TAG, "Failed to decode payload", e);
            }
        }
        if (infile != null && !infile.isEmpty()) {
            try {
                File f = new File(infile);
                if (f.exists() && f.length() > 0) {
                    byte[] buf = new byte[(int) f.length()];
                    FileInputStream fis = new FileInputStream(f);
                    try {
                        int off = 0;
                        while (off < buf.length) {
                            int n = fis.read(buf, off, buf.length - off);
                            if (n < 0) break;
                            off += n;
                        }
                    } finally {
                        fis.close();
                    }
                    return buf;
                }
            } catch (Exception e) {
                Log.e(TAG, "Failed to read infile", e);
            }
        }
        return null;
    }

    private synchronized void ensureNativeInit() {
        if (nativeInitialized) return;

        byte[] certBytes = SDKCipherNative.getCertBytes();
        FakeVivoContext fakeCtx = new FakeVivoContext(
            getApplicationContext(),
            TARGET_PACKAGE,
            certBytes
        );

        nativeInitialized = SDKCipherNative.init(fakeCtx);
        Log.i(TAG, "Native init: " + nativeInitialized);

        if (!nativeInitialized) {
            throw new RuntimeException("libvivoseckey init failed");
        }
    }

    private byte[] nativeEncrypt(byte[] data) {
        NativeRequest req = new NativeRequest(1, 1, 2, data);
        NativeResponse resp = SDKCipherNative.execute(req);
        if (resp != null && resp.err == 0) {
            return resp.output;
        }
        Log.e(TAG, "encrypt failed: err=" + (resp != null ? resp.err : "null"));
        return null;
    }

    private byte[] nativeDecrypt(byte[] data) {
        NativeRequest req = new NativeRequest(2, 1, 2, data);
        NativeResponse resp = SDKCipherNative.execute(req);
        if (resp != null && resp.err == 0) {
            return resp.output;
        }
        Log.e(TAG, "decrypt failed: err=" + (resp != null ? resp.err : "null"));
        return null;
    }

    private void writeFile(String path, byte[] data) {
        if (path == null || path.isEmpty()) return;
        try {
            File f = new File(path);
            File parent = f.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }
            FileOutputStream fos = new FileOutputStream(f);
            try {
                fos.write(data);
                fos.flush();
            } finally {
                fos.close();
            }
            f.setReadable(true, false);
            Log.i(TAG, "wrote " + path + " (" + data.length + " bytes)");
        } catch (IOException e) {
            Log.e(TAG, "writeFile failed: " + path, e);
        }
    }
}
