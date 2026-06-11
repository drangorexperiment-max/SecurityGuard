package com.securityguard.engine

import android.content.Context
import android.content.pm.PackageManager
import com.securityguard.model.*
import com.securityguard.util.Utils

/**
 * Движок вычисления общего рейтинга безопасности
 * Анализирует все аспекты системы и формирует комплексную оценку
 */
class SecurityScoreEngine(private val context: Context) {

    /**
     * Вычислить полный рейтинг безопасности
     */
    suspend fun calculateSecurityScore(): SecurityScore {
        val malwareScore = calculateMalwareScore()
        val permissionScore = calculatePermissionScore()
        val networkScore = calculateNetworkScore()
        val privacyScore = calculatePrivacyScore()
        val autostartScore = calculateAutostartScore()
        val systemScore = calculateSystemScore()

        val overall = listOf(
            malwareScore, permissionScore, networkScore,
            privacyScore, autostartScore, systemScore
        ).average().toInt()

        val details = collectDetails()

        return SecurityScore(
            overallScore = overall.coerceIn(0, 100),
            malwareScore = malwareScore.coerceIn(0, 100),
            permissionScore = permissionScore.coerceIn(0, 100),
            networkScore = networkScore.coerceIn(0, 100),
            privacyScore = privacyScore.coerceIn(0, 100),
            autostartScore = autostartScore.coerceIn(0, 100),
            systemScore = systemScore.coerceIn(0, 100),
            details = details
        )
    }

    /**
     * Оценка защиты от вредоносного ПО
     */
    private fun calculateMalwareScore(): Int {
        var score = 100
        val pm = context.packageManager
        val packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)

        for (pkg in packages) {
            if (Utils.isSystemApp(pkg.applicationInfo)) continue

            val perms = pkg.requestedPermissions?.toList() ?: emptyList()

            // Проверка на критические комбинации разрешений
            val hasSms = perms.any { it.contains("SMS") }
            val hasInternet = perms.contains("android.permission.INTERNET")
            val hasCamera = perms.contains("android.permission.CAMERA")
            val hasMic = perms.contains("android.permission.RECORD_AUDIO")
            val hasContacts = perms.any { it.contains("CONTACT") }
            val hasLocation = perms.any { it.contains("LOCATION") }
            val hasCall = perms.any { it.contains("CALL") }

            // SMS + Internet = потенциальная утечка
            if (hasSms && hasInternet) score -= 5

            // Camera + Internet = шпионская активность
            if (hasCamera && hasInternet && hasMic) score -= 5

            // Все данные + Internet
            if (hasContacts && hasLocation && hasInternet && hasMic) score -= 8

            // Root-подобные разрешения
            if (perms.contains("android.permission.WRITE_SETTINGS") &&
                perms.contains("android.permission.SYSTEM_ALERT_WINDOW")) {
                score -= 3
            }
        }

        return score.coerceAtLeast(0)
    }

    /**
     * Оценка безопасности разрешений
     */
    private fun calculatePermissionScore(): Int {
        var score = 100
        val pm = context.packageManager
        val packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)

        var totalDangerous = 0
        var totalCritical = 0

        for (pkg in packages) {
            if (Utils.isSystemApp(pkg.applicationInfo)) continue

            val perms = pkg.requestedPermissions?.toList() ?: emptyList()
            val dangerous = perms.count { it in Utils.DANGEROUS_PERMISSIONS }
            val critical = perms.count { it in Utils.CRITICAL_PERMISSIONS }

            totalDangerous += dangerous
            totalCritical += critical

            // Штраф за каждое критическое разрешение
            score -= critical * 2
        }

        // Штраф за общее количество опасных разрешений
        if (totalDangerous > 50) score -= 10
        if (totalCritical > 10) score -= 15

        return score.coerceAtLeast(0)
    }

    /**
     * Оценка сетевой безопасности
     */
    private fun calculateNetworkScore(): Int {
        var score = 100

        try {
            val networkEngine = NetworkEngine(context)
            val stats = networkEngine.getNetworkStats()

            // Штраф за подозрительные соединения
            score -= stats.suspiciousConnections * 5

            // Штраф за количество внешних соединений
            val externalConns = stats.connections.count {
                !Utils.isPrivateIp(it.remoteAddress) && it.isEstablished
            }
            if (externalConns > 20) score -= 10
            if (externalConns > 50) score -= 15

        } catch (e: Exception) {
            // Если нет доступа к сети
            score -= 5
        }

        return score.coerceAtLeast(0)
    }

    /**
     * Оценка приватности
     */
    private fun calculatePrivacyScore(): Int {
        var score = 100
        val pm = context.packageManager
        val packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)

        var trackingApps = 0
        var appsWithLocation = 0
        var appsWithCamera = 0
        var appsWithMic = 0

        for (pkg in packages) {
            if (Utils.isSystemApp(pkg.applicationInfo)) continue

            val perms = pkg.requestedPermissions?.toList() ?: emptyList()

            val tracking = perms.count { it in Utils.TRACKING_PERMISSIONS }
            if (tracking >= 3) trackingApps++

            if (perms.any { it.contains("LOCATION") }) appsWithLocation++
            if (perms.contains("android.permission.CAMERA")) appsWithCamera++
            if (perms.contains("android.permission.RECORD_AUDIO")) appsWithMic++
        }

        // Штрафы
        score -= trackingApps * 3
        if (appsWithLocation > 10) score -= 10
        if (appsWithCamera > 5) score -= 5
        if (appsWithMic > 5) score -= 5

        return score.coerceAtLeast(0)
    }

    /**
     * Оценка автозапусков
     */
    private fun calculateAutostartScore(): Int {
        return try {
            val engine = AutostartEngine(context)
            engine.getAutostartSecurityScore()
        } catch (e: Exception) {
            70 // Среднее значение при ошибке
        }
    }

    /**
     * Оценка безопасности системы
     */
    private fun calculateSystemScore(): Int {
        var score = 100

        // Проверка на root
        if (isDeviceRooted()) {
            score -= 30
        }

        // Проверка на отладку по USB
        if (android.provider.Settings.Global.getInt(
                context.contentResolver,
                android.provider.Settings.Global.ADB_ENABLED, 0
            ) == 1
        ) {
            score -= 10
        }

        // Проверка на неизвестные источники
        if (android.provider.Settings.Secure.getInt(
                context.contentResolver,
                android.provider.Settings.Secure.INSTALL_NON_MARKET_APPS, 0
            ) == 1
        ) {
            score -= 15
        }

        // Проверка версии Android
        val sdkVersion = android.os.Build.VERSION.SDK_INT
        if (sdkVersion < 28) { // Android 9
            score -= 20
        } else if (sdkVersion < 30) { // Android 11
            score -= 10
        }

        // Проверка шифрования
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
            // На Android 10+ шифрование включено по умолчанию
        } else {
            val devicePolicyManager = context.getSystemService(Context.DEVICE_POLICY_SERVICE)
                as android.app.admin.DevicePolicyManager
            if (!devicePolicyManager.storageEncryptionStatusIsActive) {
                score -= 10
            }
        }

        // Проверка блокировки экрана
        val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE)
                as android.app.KeyguardManager
        if (!keyguardManager.isDeviceSecure) {
            score -= 15
        }

        return score.coerceAtLeast(0)
    }

    /**
     * Проверка на root
     */
    private fun isDeviceRooted(): Boolean {
        // Проверка через несколько методов
        val paths = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su",
            "/magisk/.core/bin/su",
            "/system/app/SuperSU",
            "/system/app/SuperSU.apk"
        )

        for (path in paths) {
            if (java.io.File(path).exists()) return true
        }

        // Попытка запустить su
        return try {
            val process = Runtime.getRuntime().exec("su")
            process.outputStream.write("exit\n".toByteArray())
            process.outputStream.flush()
            process.waitFor()
            process.exitValue() == 0
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Сбор подробной информации
     */
    private fun collectDetails(): SecurityDetails {
        val pm = context.packageManager
        val packages = pm.getInstalledPackages(0)

        val systemApps = packages.count { Utils.isSystemApp(it.applicationInfo) }
        val userApps = packages.size - systemApps

        var dangerousApps = 0
        var criticalPerms = 0

        val permPackages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        for (pkg in permPackages) {
            if (Utils.isSystemApp(pkg.applicationInfo)) continue
            val perms = pkg.requestedPermissions?.toList() ?: emptyList()
            val dangerous = perms.count { it in Utils.DANGEROUS_PERMISSIONS }
            if (dangerous > 3) dangerousApps++
            criticalPerms += perms.count { it in Utils.CRITICAL_PERMISSIONS }
        }

        val processEngine = ProcessEngine(context)
        val processes = processEngine.getRunningProcesses()

        val prefs = context.getSharedPreferences("security_guard", Context.MODE_PRIVATE)

        return SecurityDetails(
            installedApps = userApps,
            systemApps = systemApps,
            dangerousApps = dangerousApps,
            criticalPermissions = criticalPerms,
            autostartApps = 0, // Загружается отдельно
            activeConnections = 0, // Загружается отдельно
            runningProcesses = processes.size,
            suspiciousProcesses = processes.count { it.riskScore > 50 },
            threats = prefs.getInt("total_threats", 0),
            lastScanTime = prefs.getLong("last_scan_time", 0L)
        )
    }
}
