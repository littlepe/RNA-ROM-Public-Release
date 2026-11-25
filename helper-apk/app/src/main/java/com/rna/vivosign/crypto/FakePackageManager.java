package com.rna.vivosign.crypto;

import android.content.ComponentName;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.ChangedPackages;
import android.content.pm.FeatureInfo;
import android.content.pm.InstrumentationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageInstaller;
import android.content.pm.PackageManager;
import android.content.pm.PermissionGroupInfo;
import android.content.pm.PermissionInfo;
import android.content.pm.ProviderInfo;
import android.content.pm.ResolveInfo;
import android.content.pm.ServiceInfo;
import android.content.pm.SharedLibraryInfo;
import android.content.pm.Signature;
import android.content.pm.VersionedPackage;
import android.content.res.Resources;
import android.content.res.XmlResourceParser;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.UserHandle;

import java.util.List;

@SuppressWarnings("deprecation")
public class FakePackageManager extends PackageManager {

    private final PackageManager real;
    private final String targetPackage;
    private final String realPackage;
    private final byte[] fakeCertBytes;

    public FakePackageManager(PackageManager real, String targetPackage, String realPackage, byte[] fakeCertBytes) {
        this.real = real;
        this.targetPackage = targetPackage;
        this.realPackage = realPackage;
        this.fakeCertBytes = fakeCertBytes;
    }

    @Override
    public PackageInfo getPackageInfo(String packageName, int flags) throws NameNotFoundException {
        String lookup = targetPackage.equals(packageName) ? realPackage : packageName;
        PackageInfo pi = real.getPackageInfo(lookup, flags);
        if (targetPackage.equals(packageName)) {
            pi.packageName = targetPackage;
            if ((flags & GET_SIGNATURES) != 0) {
                pi.signatures = new Signature[]{new Signature(fakeCertBytes)};
            }
        }
        return pi;
    }

    @Override
    public PackageInfo getPackageInfo(VersionedPackage versionedPackage, int flags) throws NameNotFoundException {
        if (targetPackage.equals(versionedPackage.getPackageName())) {
            versionedPackage = new VersionedPackage(realPackage, versionedPackage.getVersionCode());
        }
        return real.getPackageInfo(versionedPackage, flags);
    }

    @Override
    public boolean isPermissionRevokedByPolicy(String permission, String packageName) {
        return false;
    }

    @Override
    public void addPackageToPreferred(String packageName) { real.addPackageToPreferred(packageName); }

    @Override
    public boolean addPermission(PermissionInfo permission) { return real.addPermission(permission); }

    @Override
    public boolean addPermissionAsync(PermissionInfo permission) { return real.addPermissionAsync(permission); }

    @Override
    public void addPreferredActivity(IntentFilter filter, int match, ComponentName[] set, ComponentName activity) { real.addPreferredActivity(filter, match, set, activity); }

    @Override
    public boolean canRequestPackageInstalls() { return real.canRequestPackageInstalls(); }

    @Override
    public String[] canonicalToCurrentPackageNames(String[] names) { return real.canonicalToCurrentPackageNames(names); }

    @Override
    public int checkPermission(String permName, String pkgName) { return real.checkPermission(permName, pkgName); }

    @Override
    public int checkSignatures(int uid1, int uid2) { return real.checkSignatures(uid1, uid2); }

    @Override
    public int checkSignatures(String pkg1, String pkg2) { return real.checkSignatures(pkg1, pkg2); }

    @Override
    public void clearInstantAppCookie() { real.clearInstantAppCookie(); }

    @Override
    public void clearPackagePreferredActivities(String packageName) { real.clearPackagePreferredActivities(packageName); }

    @Override
    public String[] currentToCanonicalPackageNames(String[] names) { return real.currentToCanonicalPackageNames(names); }

    @Override
    public void extendVerificationTimeout(int sessionId, int secondsToDelay, long millisecondsToExtend) { real.extendVerificationTimeout(sessionId, secondsToDelay, millisecondsToExtend); }

    @Override
    public Drawable getActivityBanner(ComponentName activityName) throws NameNotFoundException { return real.getActivityBanner(activityName); }

    @Override
    public Drawable getActivityBanner(Intent intent) throws NameNotFoundException { return real.getActivityBanner(intent); }

    @Override
    public Drawable getActivityIcon(ComponentName activityName) throws NameNotFoundException { return real.getActivityIcon(activityName); }

    @Override
    public Drawable getActivityIcon(Intent intent) throws NameNotFoundException { return real.getActivityIcon(intent); }

    @Override
    public ActivityInfo getActivityInfo(ComponentName component, int flags) throws NameNotFoundException { return real.getActivityInfo(component, flags); }

    @Override
    public Drawable getActivityLogo(ComponentName activityName) throws NameNotFoundException { return real.getActivityLogo(activityName); }

    @Override
    public Drawable getActivityLogo(Intent intent) throws NameNotFoundException { return real.getActivityLogo(intent); }

    @Override
    public List<PermissionGroupInfo> getAllPermissionGroups(int flags) { return real.getAllPermissionGroups(flags); }

    @Override
    public Drawable getApplicationBanner(ApplicationInfo app) { return real.getApplicationBanner(app); }

    @Override
    public Drawable getApplicationBanner(String packageName) throws NameNotFoundException { return real.getApplicationBanner(packageName); }

    @Override
    public int getApplicationEnabledSetting(String packageName) { return real.getApplicationEnabledSetting(packageName); }

    @Override
    public Drawable getApplicationIcon(ApplicationInfo app) { return real.getApplicationIcon(app); }

    @Override
    public Drawable getApplicationIcon(String packageName) throws NameNotFoundException { return real.getApplicationIcon(packageName); }

    @Override
    public ApplicationInfo getApplicationInfo(String packageName, int flags) throws NameNotFoundException { return real.getApplicationInfo(packageName, flags); }

    @Override
    public CharSequence getApplicationLabel(ApplicationInfo info) { return real.getApplicationLabel(info); }

    @Override
    public Drawable getApplicationLogo(ApplicationInfo app) { return real.getApplicationLogo(app); }

    @Override
    public Drawable getApplicationLogo(String packageName) throws NameNotFoundException { return real.getApplicationLogo(packageName); }

    @Override
    public ChangedPackages getChangedPackages(int sinceSequenceNumber) { return real.getChangedPackages(sinceSequenceNumber); }

    @Override
    public int getComponentEnabledSetting(ComponentName componentName) { return real.getComponentEnabledSetting(componentName); }

    @Override
    public Drawable getDefaultActivityIcon() { return real.getDefaultActivityIcon(); }

    @Override
    public Drawable getDrawable(String packageName, int resid, ApplicationInfo appInfo) { return real.getDrawable(packageName, resid, appInfo); }

    @Override
    public List<ApplicationInfo> getInstalledApplications(int flags) { return real.getInstalledApplications(flags); }

    @Override
    public List<PackageInfo> getInstalledPackages(int flags) { return real.getInstalledPackages(flags); }

    @Override
    public String getInstallerPackageName(String packageName) { return real.getInstallerPackageName(packageName); }

    @Override
    public byte[] getInstantAppCookie() { return real.getInstantAppCookie(); }

    @Override
    public int getInstantAppCookieMaxBytes() { return real.getInstantAppCookieMaxBytes(); }

    @Override
    public InstrumentationInfo getInstrumentationInfo(ComponentName className, int flags) throws NameNotFoundException { return real.getInstrumentationInfo(className, flags); }

    @Override
    public Intent getLaunchIntentForPackage(String packageName) { return real.getLaunchIntentForPackage(packageName); }

    @Override
    public Intent getLeanbackLaunchIntentForPackage(String packageName) { return real.getLeanbackLaunchIntentForPackage(packageName); }

    @Override
    public String getNameForUid(int uid) { return real.getNameForUid(uid); }

    @Override
    public int[] getPackageGids(String packageName) throws NameNotFoundException { return real.getPackageGids(packageName); }

    @Override
    public int[] getPackageGids(String packageName, int flags) throws NameNotFoundException { return real.getPackageGids(packageName, flags); }

    @Override
    public PackageInstaller getPackageInstaller() { return real.getPackageInstaller(); }

    @Override
    public int getPackageUid(String packageName, int flags) throws NameNotFoundException { return real.getPackageUid(packageName, flags); }

    @Override
    public String[] getPackagesForUid(int uid) { return real.getPackagesForUid(uid); }

    @Override
    public List<PackageInfo> getPackagesHoldingPermissions(String[] permissions, int flags) { return real.getPackagesHoldingPermissions(permissions, flags); }

    @Override
    public PermissionGroupInfo getPermissionGroupInfo(String groupName, int flags) throws NameNotFoundException { return real.getPermissionGroupInfo(groupName, flags); }

    @Override
    public PermissionInfo getPermissionInfo(String permissionName, int flags) throws NameNotFoundException { return real.getPermissionInfo(permissionName, flags); }

    @Override
    public int getPreferredActivities(List<IntentFilter> outFilters, List<ComponentName> outActivities, String packageName) { return real.getPreferredActivities(outFilters, outActivities, packageName); }

    @Override
    public List<PackageInfo> getPreferredPackages(int flags) { return real.getPreferredPackages(flags); }

    @Override
    public ProviderInfo getProviderInfo(ComponentName className, int flags) throws NameNotFoundException { return real.getProviderInfo(className, flags); }

    @Override
    public ActivityInfo getReceiverInfo(ComponentName className, int flags) throws NameNotFoundException { return real.getReceiverInfo(className, flags); }

    @Override
    public Resources getResourcesForActivity(ComponentName activityName) throws NameNotFoundException { return real.getResourcesForActivity(activityName); }

    @Override
    public Resources getResourcesForApplication(ApplicationInfo app) throws NameNotFoundException { return real.getResourcesForApplication(app); }

    @Override
    public Resources getResourcesForApplication(String appPackageName) throws NameNotFoundException { return real.getResourcesForApplication(appPackageName); }

    @Override
    public ServiceInfo getServiceInfo(ComponentName className, int flags) throws NameNotFoundException { return real.getServiceInfo(className, flags); }

    @Override
    public List<SharedLibraryInfo> getSharedLibraries(int flags) { return real.getSharedLibraries(flags); }

    @Override
    public FeatureInfo[] getSystemAvailableFeatures() { return real.getSystemAvailableFeatures(); }

    @Override
    public String[] getSystemSharedLibraryNames() { return real.getSystemSharedLibraryNames(); }

    @Override
    public CharSequence getText(String packageName, int resId, ApplicationInfo appInfo) { return real.getText(packageName, resId, appInfo); }

    @Override
    public Drawable getUserBadgedDrawableForDensity(Drawable drawable, UserHandle user, Rect badgeLocation, int density) { return real.getUserBadgedDrawableForDensity(drawable, user, badgeLocation, density); }

    @Override
    public Drawable getUserBadgedIcon(Drawable icon, UserHandle user) { return real.getUserBadgedIcon(icon, user); }

    @Override
    public CharSequence getUserBadgedLabel(CharSequence label, UserHandle user) { return real.getUserBadgedLabel(label, user); }

    @Override
    public XmlResourceParser getXml(String packageName, int resid, ApplicationInfo appInfo) { return real.getXml(packageName, resid, appInfo); }

    @Override
    public boolean hasSystemFeature(String name) { return real.hasSystemFeature(name); }

    @Override
    public boolean hasSystemFeature(String name, int version) { return real.hasSystemFeature(name, version); }

    @Override
    public boolean isInstantApp() { return real.isInstantApp(); }

    @Override
    public boolean isInstantApp(String packageName) { return real.isInstantApp(packageName); }

    @Override
    public boolean isSafeMode() { return real.isSafeMode(); }

    @Override
    public List<ResolveInfo> queryBroadcastReceivers(Intent intent, int flags) { return real.queryBroadcastReceivers(intent, flags); }

    @Override
    public List<ProviderInfo> queryContentProviders(String processName, int uid, int flags) { return real.queryContentProviders(processName, uid, flags); }

    @Override
    public List<InstrumentationInfo> queryInstrumentation(String targetPackage, int flags) { return real.queryInstrumentation(targetPackage, flags); }

    @Override
    public List<ResolveInfo> queryIntentActivities(Intent intent, int flags) { return real.queryIntentActivities(intent, flags); }

    @Override
    public List<ResolveInfo> queryIntentActivityOptions(ComponentName caller, Intent[] specificFilters, Intent intent, int flags) { return real.queryIntentActivityOptions(caller, specificFilters, intent, flags); }

    @Override
    public List<ResolveInfo> queryIntentContentProviders(Intent intent, int flags) { return real.queryIntentContentProviders(intent, flags); }

    @Override
    public List<ResolveInfo> queryIntentServices(Intent intent, int flags) { return real.queryIntentServices(intent, flags); }

    @Override
    public List<PermissionInfo> queryPermissionsByGroup(String group, int flags) throws NameNotFoundException { return real.queryPermissionsByGroup(group, flags); }

    @Override
    public void removePackageFromPreferred(String packageName) { real.removePackageFromPreferred(packageName); }

    @Override
    public void removePermission(String permissionName) { real.removePermission(permissionName); }

    @Override
    public ResolveInfo resolveActivity(Intent intent, int flags) { return real.resolveActivity(intent, flags); }

    @Override
    public ProviderInfo resolveContentProvider(String name, int flags) { return real.resolveContentProvider(name, flags); }

    @Override
    public ResolveInfo resolveService(Intent intent, int flags) { return real.resolveService(intent, flags); }

    @Override
    public void setApplicationCategoryHint(String packageName, int categoryHint) { real.setApplicationCategoryHint(packageName, categoryHint); }

    @Override
    public void setApplicationEnabledSetting(String packageName, int newState, int flags) { real.setApplicationEnabledSetting(packageName, newState, flags); }

    @Override
    public void setComponentEnabledSetting(ComponentName componentName, int newState, int flags) { real.setComponentEnabledSetting(componentName, newState, flags); }

    @Override
    public void setInstallerPackageName(String targetPackage, String installerPackageName) { real.setInstallerPackageName(targetPackage, installerPackageName); }

    @Override
    public void updateInstantAppCookie(byte[] cookie) { real.updateInstantAppCookie(cookie); }

    @Override
    public void verifyPendingInstall(int id, int verificationStatus) { real.verifyPendingInstall(id, verificationStatus); }
}
