# Security Guard ProGuard Rules

# Keep models (used in JSON serialization)
-keepclassmembers class com.securityguard.model.** {
    *;
}

# Keep parcelable classes
-keepclassmembers class * implements android.os.Parcelable {
    public static final ** CREATOR;
}

# Gson
-keepattributes Signature
-keepattributes *Annotation*
-dontwarn sun.misc.**

# Kotlin
-dontwarn kotlin.**
-keep class kotlin.Metadata { *; }
