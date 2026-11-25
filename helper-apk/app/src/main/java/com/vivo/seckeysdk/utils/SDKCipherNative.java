package com.vivo.seckeysdk.utils;

import android.content.Context;
import android.content.pm.Signature;
import android.util.Base64;
import android.util.Log;

public class SDKCipherNative {

    private static final String TAG = "SDKCipherNative";

    static {
        System.loadLibrary("vivoseckey");
    }

    public static native boolean notice();

    public static native boolean init(Context ctx);

    public static native NativeResponse execute(NativeRequest request);

    static final String HARDCODED_CERT_BASE64 =
        "MIIEpTCCA42gAwIBAgIJALFTcw2KNSU5MA0GCSqGSIb3DQEBBQUAMIGTMQswCQYD" +
        "VQQGEwJDTjESMBAGA1UECBMJR3Vhbmdkb25nMRYwFAYDVQQHEw1Eb25nZ3VhbiBW" +
        "aWV3MQwwCgYDVQQKEwNCQksxDTALBgNVBAsTBElRT08xGTAXBgNVBAMTEGJia21v" +
        "YmlsZS5jb20uY24xIDAeBgkqhkiG9w0BCQEWEWJia3RlbEBiYmt0ZWwuY29tMB4X" +
        "DTEyMDkyNTE0MTk0M1oXDTQwMDIxMTE0MTk0M1owgZMxCzAJBgNVBAYTAkNOMRIw" +
        "EAYDVQQIEwlHdWFuZ2RvbmcxFjAUBgNVBAcTDURvbmdndWFuIFZpZXcxDDAKBgNV" +
        "BAoTA0JCSzENMAsGA1UECxMESVFPTzEZMBcGA1UEAxMQYmJrbW9iaWxlLmNvbS5j" +
        "bjEgMB4GCSqGSIb3DQEJARYRYmJrdGVsQGJia3RlbC5jb20wggEgMA0GCSqGSIb3" +
        "DQEBAQUAA4IBDQAwggEIAoIBAQCsfq1NAQO0ozLJgT4T+wFockr5RMA2WHvQcltj" +
        "KFDbI2MFSN4QwUqHbcUFMRZsiKu1c3fiGTNk+Py8fhQu3GMY6fv1rJtv9qaHEjtk" +
        "WleoemiH1z5rAr9Kipr6/jDwYbijDuPAK8XgNUCRWCZi1ci98Ve11wUQvcoYp1mz" +
        "gHuWi9eCtkZZyz4Ci47XmV5KfJGYajOMHSURjC1kzbdayUyUAskXiLqbmTT5NlPI" +
        "yB7xcGNGUfaXpyLR+Pg0xlKQoweqgVZ2I5Nems1E9aEckTuTVTmsUqSAKvgDQaFt" +
        "ksRXudAnwTRlEt5qjuiFxTD7Dzu3AY7PpsIIZFICcG/DaPOJAgEDo4H7MIH4MB0G" +
        "A1UdDgQWBBSw7I/j7ruoUyXz7Z+O03SdoYNzIzCByAYDVR0jBIHAMIG9gBSw7I/j" +
        "7ruoUyXz7Z+O03SdoYNzI6GBmaSBljCBkzELMAkGA1UEBhMCQ04xEjAQBgNVBAgT" +
        "CUd1YW5nZG9uZzEWMBQGA1UEBxMNRG9uZ2d1YW4gVmlldzEMMAoGA1UEChMDQkJL" +
        "MQ0wCwYDVQQLEwRJUU9PMRkwFwYDVQQDExBiYmttb2JpbGUuY29tLmNuMSAwHgYJ" +
        "KoZIhvcNAQkBFhFiYmt0ZWxAYmJrdGVsLmNvbYIJALFTcw2KNSU5MAwGA1UdEwQF" +
        "MAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAH0tVFLHuJb1QT6CQrRFyuQRfZOCSlcl" +
        "O+lRokupKoMHISFRhLU1c/G4OFJrDEHqUZtJaFL8oy4Z9of+irsTx8BGGwXRarWF" +
        "qNVMVjdXXO0vHj9gKSZwSxbfoUkIEkFkCSmPA/U7+j/zls/y2vEu/HV4Y64C9kWj" +
        "mZlRqVe2A4Pn9ue276baHqF9pljaEqwQ+qLVzW7MVAND3vOCkzQtmc/EIN8fQ3pp" +
        "vyTpy9drhVBfNoPiA4qBn2L7RAYcEi7B+SBTPntpfPJ+iw8qra2MM/wjw9/7TAml" +
        "7UxMKbxf/V2+/ROj1mkTLWxKBnwTU+BY4k0W/i0YI7Zvqi1A0G9cABA=";

    public static byte[] getCertBytes() {
        return Base64.decode(HARDCODED_CERT_BASE64, Base64.DEFAULT);
    }

    public static Signature[] cCert(String name) {
        try {
            byte[] certBytes = getCertBytes();
            Signature sig = new Signature(certBytes);
            return new Signature[]{sig};
        } catch (Exception e) {
            Log.e(TAG, "cCert failed", e);
        }
        return new Signature[0];
    }
}
