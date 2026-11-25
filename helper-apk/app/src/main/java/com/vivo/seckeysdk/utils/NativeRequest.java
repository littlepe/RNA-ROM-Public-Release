package com.vivo.seckeysdk.utils;

public class NativeRequest {
    public int operateType;
    public int encryptType;
    public int keyVersion;
    public byte[] data;

    public NativeRequest(int operateType, int encryptType, int keyVersion, byte[] data) {
        this.operateType = operateType;
        this.encryptType = encryptType;
        this.keyVersion = keyVersion;
        this.data = data;
    }

    public byte[] getData() { return data; }
    public int getOperateType() { return operateType; }
    public int getEncryptType() { return encryptType; }
    public int getKeyVersion() { return keyVersion; }
    public byte[] getIV() { return new byte[16]; }
    public byte[] getGaloisMAC() { return new byte[16]; }
    public byte[] getNonce() { return new byte[16]; }
}
