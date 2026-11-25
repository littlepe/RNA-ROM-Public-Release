package com.rna.vivosign.crypto;

import android.content.Context;
import android.content.pm.PackageManager;
import android.content.ContextWrapper;

public class FakeVivoContext extends ContextWrapper {

    private final String targetPackage;
    private final byte[] fakeCertBytes;

    public FakeVivoContext(Context base, String targetPackage, byte[] fakeCertBytes) {
        super(base);
        this.targetPackage = targetPackage;
        this.fakeCertBytes = fakeCertBytes;
    }

    @Override
    public String getPackageName() {
        return targetPackage;
    }

    @Override
    public PackageManager getPackageManager() {
        return new FakePackageManager(
            super.getPackageManager(),
            targetPackage,
            super.getPackageName(),
            fakeCertBytes
        );
    }
}
