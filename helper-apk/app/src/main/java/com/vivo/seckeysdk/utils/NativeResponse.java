package com.vivo.seckeysdk.utils;

public class NativeResponse {
    public int err;
    public byte[] output;
    public int keyVersion;
    public byte[] pubicKeyHash;

    public void setErr(int err) { this.err = err; }
    public void setOutput(byte[] output) { this.output = output; }
    public void setKeyVersion(int keyVersion) { this.keyVersion = keyVersion; }
    public void setPubicKeyHash(byte[] hash) { this.pubicKeyHash = hash; }
}
