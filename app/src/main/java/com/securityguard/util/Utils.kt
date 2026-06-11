package com.securityguard.util

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.PackageInfo
import android.content.pm.ApplicationInfo
import android.content.pm.Signature
import android.os.Build
import java.io.File
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object Utils {

    /**
     * Получить SHA-256 хеш файла
     */
    fun getFileHash(filePath: String): String {
        return try {
            val file = File(filePath)
            if (!file.exists() || !file.canRead()) return ""
            val digest = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { fis ->
                val buffer = ByteArray(8192)
                var read: Int
                while (fis.read(buffer).also { read = it } != -1) {
                    digest.update(buffer, 0, read)
                }
            }
            digest.digest().joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            ""
        }
    }

    /**
     * Получить MD5 хеш файла
     */
    fun getFileMd5(filePath: String): String {
        return try {
            val file = File(filePath)
            if (!file.exists() || !file.canRead()) return ""
            val digest = MessageDigest.getInstance("MD5")
            file.inputStream().use { fis ->
                val buffer = ByteArray(8192)
                var read: Int
                while (fis.read(buffer).also { read = it } != -1) {
                    digest.update(buffer, 0, read)
                }
            }
            digest.digest().joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            ""
        }
    }

    /**
     * Получить SHA-256 подпись APK
     */
    fun getApkSignature(context: Context, packageName: String): List<String> {
        return try {
            val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                context.packageManager.getPackageInfo(
                    packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getPackageInfo(
                    packageName,
                    PackageManager.GET_SIGNATURES
                )
            }

            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo.signingInfo?.apkContentsSigners ?: arrayOf()
            } else {
                @Suppress("DEPRECATION")
                packageInfo.signatures ?: arrayOf()
            }

            signatures.map { sig ->
                val digest = MessageDigest.getInstance("SHA-256")
                digest.update(sig.toByteArray())
                digest.digest().joinToString(":") { "%02X".format(it) }
            }
        } catch (e: Exception) {
            emptyList()
        }
    }

    /**
     * Проверить, является ли приложение системным
     */
    fun isSystemApp(applicationInfo: ApplicationInfo): Boolean {
        return (applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0 ||
                (applicationInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
    }

    /**
     * Форматирование размера файла
     */
    fun formatSize(bytes: Long): String {
        return when {
            bytes < 1024 -> "$bytes B"
            bytes < 1024 * 1024 -> String.format("%.1f KB", bytes / 1024.0)
            bytes < 1024 * 1024 * 1024 -> String.format("%.1f MB", bytes / (1024.0 * 1024))
            else -> String.format("%.1f GB", bytes / (1024.0 * 1024 * 1024))
        }
    }

    /**
     * Форматирование времени
     */
    fun formatTime(timestamp: Long): String {
        val sdf = SimpleDateFormat("dd.MM.yyyy HH:mm:ss", Locale.getDefault())
        return sdf.format(Date(timestamp))
    }

    /**
     * Форматирование длительности
     */
    fun formatDuration(millis: Long): String {
        val seconds = millis / 1000
        return when {
            seconds < 60 -> "$seconds сек"
            seconds < 3600 -> "${seconds / 60} мин ${seconds % 60} сек"
            else -> "${seconds / 3600} ч ${(seconds % 3600) / 60} мин"
        }
    }

    /**
     * Список опасных разрешений Android
     */
    val DANGEROUS_PERMISSIONS = setOf(
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.READ_PHONE_STATE",
        "android.permission.CALL_PHONE",
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_CALENDAR",
        "android.permission.WRITE_CALENDAR",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "android.permission.BODY_SENSORS",
        "android.permission.ACTIVITY_RECOGNITION",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_MEDIA_AUDIO",
        "android.permission.POST_NOTIFICATIONS",
        "android.permission.NEARBY_WIFI_DEVICES",
        "android.permission.BLUETOOTH_CONNECT",
        "android.permission.BLUETOOTH_SCAN",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.ANSWER_PHONE_CALLS",
        "android.permission.ACCEPT_HANDOVER",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.WRITE_SETTINGS",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.DRAW_OVER_OTHER_APPS",
        "android.permission.GET_ACCOUNTS",
        "android.permission.USE_CREDENTIALS",
        "android.permission.SUBSCRIBED_FEEDS_WRITE"
    )

    /**
     * Супер-опасные разрешения (высший уровень риска)
     */
    val CRITICAL_PERMISSIONS = setOf(
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.CALL_PHONE",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.WRITE_SETTINGS",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG"
    )

    /**
     * Разрешения, связанные с трекингом
     */
    val TRACKING_PERMISSIONS = setOf(
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.BLUETOOTH_SCAN",
        "android.permission.BLUETOOTH_CONNECT",
        "android.permission.NEARBY_WIFI_DEVICES",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.ACCESS_WIFI_STATE"
    )

    /**
     * Подозрительные имена файлов
     */
    val SUSPICIOUS_FILE_PATTERNS = listOf(
        Regex(".*\\.(apk|dex|jar|so)$", RegexOption.IGNORE_CASE),
        Regex(".*\\.(exe|dll|bat|cmd|ps1|vbs|js)$", RegexOption.IGNORE_CASE),
        Regex(".*\\.(hidden|tmp|temp)$", RegexOption.IGNORE_CASE),
        Regex(".*\\.xapk$", RegexOption.IGNORE_CASE),
        Regex("^\\..*$"), // скрытые файлы
        Regex(".*payload.*", RegexOption.IGNORE_CASE),
        Regex(".*exploit.*", RegexOption.IGNORE_CASE),
        Regex(".*hack.*", RegexOption.IGNORE_CASE),
        Regex(".*crack.*", RegexOption.IGNORE_CASE),
        Regex(".*keygen.*", RegexOption.IGNORE_CASE),
        Regex(".*patch.*", RegexOption.IGNORE_CASE)
    )

    /**
     * Подозрительные имена пакетов
     */
    val SUSPICIOUS_PACKAGE_PATTERNS = listOf(
        Regex(".*hack.*", RegexOption.IGNORE_CASE),
        Regex(".*crack.*", RegexOption.IGNORE_CASE),
        Regex(".*cheat.*", RegexOption.IGNORE_CASE),
        Regex(".*spy.*", RegexOption.IGNORE_CASE),
        Regex(".*track.*", RegexOption.IGNORE_CASE),
        Regex(".*monitor.*", RegexOption.IGNORE_CASE),
        Regex(".*keylog.*", RegexOption.IGNORE_CASE),
        Regex(".*sniff.*", RegexOption.IGNORE_CASE),
        Regex(".*inject.*", RegexOption.IGNORE_CASE),
        Regex(".*exploit.*", RegexOption.IGNORE_CASE),
        Regex(".*payload.*", RegexOption.IGNORE_CASE),
        Regex(".*backdoor.*", RegexOption.IGNORE_CASE),
        Regex(".*trojan.*", RegexOption.IGNORE_CASE),
        Regex(".*malware.*", RegexOption.IGNORE_CASE),
        Regex(".* RAT$", RegexOption.IGNORE_CASE)
    )

    /**
     * Безопасные домены
     */
    val SAFE_DOMAINS = setOf(
        "google.com", "googleapis.com", "google-analytics.com",
        "googleadservices.com", "googleusercontent.com",
        "android.com", "gstatic.com",
        "facebook.com", "fbcdn.net",
        "apple.com", "icloud.com",
        "microsoft.com", "windows.com",
        "amazonaws.com", "amazon.com",
        "cloudfront.net", "akamai.net",
        "twitter.com", "x.com",
        "github.com", "githubusercontent.com",
        "play.google.com", "firebase.google.com"
    )

    /**
     * Подозрительные порты
     */
    val SUSPICIOUS_PORTS = setOf(
        4444,   // Metasploit default
        5555,   // ADB
        6666,   // IRC
        6667,   // IRC
        1337,   // Common exploit
        31337,  // Back Orifice
        12345,  // NetBus
        27374,  // SubSeven
        10000,  // Common backdoor
        1234,   // Common backdoor
        8888,   // Common C2
        9999,   // Common C2
        3389,   // RDP
        22,     // SSH
        23      // Telnet
    )

    /**
     * Получить код страны по IP (заглушка)
     */
    fun isPrivateIp(ip: String): Boolean {
        if (ip == "0.0.0.0" || ip == "::" || ip == "*" || ip.startsWith("127.")) return true
        val parts = ip.split(".")
        if (parts.size != 4) return false
        try {
            val first = parts[0].toInt()
            val second = parts[1].toInt()
            return when {
                first == 10 -> true
                first == 172 && second in 16..31 -> true
                first == 192 && second == 168 -> true
                first == 169 && second == 254 -> true
                else -> false
            }
        } catch (e: Exception) {
            return false
        }
    }

    /**
     * Оценка риска по количеству опасных разрешений
     */
    fun calculatePermissionRisk(permissions: List<String>, criticalPerms: List<String>): Int {
        var score = 0
        // Каждое опасное разрешение добавляет очки
        score += permissions.size * 5
        // Критические разрешения добавляют больше
        score += criticalPerms.size * 15
        // Ограничение до 100
        return score.coerceAtMost(100)
    }

    /**
     * Получить цвет для уровня риска
     */
    fun getRiskColor(riskScore: Int): Int {
        return when {
            riskScore <= 20 -> android.graphics.Color.parseColor("#4CAF50") // Зелёный
            riskScore <= 40 -> android.graphics.Color.parseColor("#8BC34A") // Светло-зелёный
            riskScore <= 60 -> android.graphics.Color.parseColor("#FFC107") // Жёлтый
            riskScore <= 80 -> android.graphics.Color.parseColor("#FF9800") // Оранжевый
            else -> android.graphics.Color.parseColor("#F44336") // Красный
        }
    }
}
