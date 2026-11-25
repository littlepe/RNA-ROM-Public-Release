# Keep native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep Vivo SecKey SDK classes (used by libvivoseckey.so JNI)
-keep class com.vivo.seckeysdk.** { *; }
-keep class com.vivo.seckeysdk.utils.** { *; }
-dontwarn com.vivo.seckeysdk.**

# Keep the activity that getrom.py launches
-keep class com.rna.tools.VivoJvqActivity { *; }

# Keep crypto helpers
-keep class com.rna.vivosign.crypto.** { *; }
