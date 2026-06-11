package com.securityguard.engine

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.ApplicationInfo
import android.util.Log
import com.securityguard.model.*
import com.securityguard.util.Utils
import java.io.File
import java.util.UUID
import kotlin.math.min

/**
 * Главный движок сканирования - ядро безопасности
 * Выполняет эвристический анализ, проверку подписей, анализ разрешений,
 * обнаружение аномалий и проверку файлов
 */
class ScanEngine(private val context: Context) {

    companion object {
        private const val TAG = "ScanEngine"
    }

    private val threatDatabase = ThreatDatabase(context)

    /**
     * Полное сканирование системы
     */
    suspend fun fullScan(onProgress: (Int, String) -> Unit): ScanResult {
        val startTime = System.currentTimeMillis()
        val threats = mutableListOf<ThreatInfo>()
        var filesScanned = 0L
        val appsScanned = mutableListOf<String>()

        try {
            // Этап 1: Сканирование приложений (40%)
            onProgress(5, "Сканирование установленных приложений...")
            val apps = scanInstalledApps()
            threats.addAll(apps)
            appsScanned.addAll(apps.map { it.packageName })

            // Этап 2: Сканирование процессов (60%)
            onProgress(40, "Анализ запущенных процессов...")
            val processThreats = scanProcesses()
            threats.addAll(processThreats)

            // Этап 3: Сканирование файлов (60-90%)
            onProgress(60, "Проверка файловой системы...")
            val fileThreats = scanFileSystem { count, path ->
                filesScanned = count
                onProgress(60 + ((count % 1000) / 100), "Проверка: $path")
            }
            threats.addAll(fileThreats)

            // Этап 4: Сетевой анализ (95%)
            onProgress(95, "Анализ сетевых подключений...")
            val networkThreats = scanNetwork()
            threats.addAll(networkThreats)

            // Этап 5: Проверка автозапусков (98%)
            onProgress(98, "Проверка автозапусков...")
            val autostartThreats = scanAutostarts()
            threats.addAll(autostartThreats)

            onProgress(100, "Сканирование завершено!")

        } catch (e: Exception) {
            Log.e(TAG, "Scan error", e)
        }

        return ScanResult(
            id = UUID.randomUUID().toString(),
            scanType = ScanType.FULL,
            startTime = startTime,
            endTime = System.currentTimeMillis(),
            filesScanned = filesScanned,
            appsScanned = appsScanned.size,
            processesScanned = 0,
            threatsFound = threats,
            totalSize = 0,
            isCompleted = true
        )
    }

    /**
     * Быстрое сканирование (только приложения и ключевые зоны)
     */
    suspend fun quickScan(onProgress: (Int, String) -> Unit): ScanResult {
        val startTime = System.currentTimeMillis()
        val threats = mutableListOf<ThreatInfo>()

        // Сканирование приложений
        onProgress(10, "Быстрое сканирование приложений...")
        val appThreats = scanInstalledApps()
        threats.addAll(appThreats)

        // Сканирование процессов
        onProgress(50, "Проверка процессов...")
        val processThreats = scanProcesses()
        threats.addAll(processThreats)

        // Быстрая проверка критических папок
        onProgress(70, "Проверка критических зон...")
        val criticalDirs = listOf(
            "/sdcard/Download",
            "/sdcard/DCIM",
            "/sdcard/Android/data",
            "/sdcard/Documents",
            "/sdcard/tmp",
            "/sdcard/.tmp",
            "/data/local/tmp"
        )
        var fileCount = 0L
        for (dir in criticalDirs) {
            val fileThreats = scanDirectory(File(dir), depth = 3) { count, _ ->
                fileCount += count
                onProgress(70 + min(fileCount / 10, 25).toInt(), "Проверка: $dir")
            }
            threats.addAll(fileThreats)
        }

        onProgress(100, "Быстрое сканирование завершено!")

        return ScanResult(
            id = UUID.randomUUID().toString(),
            scanType = ScanType.QUICK,
            startTime = startTime,
            endTime = System.currentTimeMillis(),
            filesScanned = fileCount,
            appsScanned = appThreats.size,
            processesScanned = processThreats.size,
            threatsFound = threats,
            totalSize = 0,
            isCompleted = true
        )
    }

    /**
     * Сканирование установленных приложений
     */
    private fun scanInstalledApps(): List<ThreatInfo> {
        val threats = mutableListOf<ThreatInfo>()
        val pm = context.packageManager

        val packages = pm.getInstalledPackages(
            PackageManager.GET_PERMISSIONS or
            PackageManager.GET_RECEIVERS or
            PackageManager.GET_ACTIVITIES or
            PackageManager.GET_SERVICES or
            PackageManager.GET_META_DATA or
            PackageManager.GET_SIGNATURES or
            PackageManager.GET_CONFIGURATIONS
        )

        for (pkg in packages) {
            try {
                val appInfo = pkg.applicationInfo
                val appName = pm.getApplicationLabel(appInfo).toString()
                val packageName = pkg.packageName
                val isSystem = Utils.isSystemApp(appInfo)

                // Получение разрешений
                val permissions = pkg.requestedPermissions?.toList() ?: emptyList()
                val dangerousPerms = permissions.filter { it in Utils.DANGEROUS_PERMISSIONS }
                val criticalPerms = permissions.filter { it in Utils.CRITICAL_PERMISSIONS }

                // Вычисление оценки риска
                var riskScore = 0
                val riskReasons = mutableListOf<String>()

                // 1. Проверка на debuggable
                if ((appInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0 && !isSystem) {
                    riskScore += 30
                    riskReasons.add("Приложение отлаживаемое (debuggable)")
                }

                // 2. Проверка на allowBackup
                if ((appInfo.flags and ApplicationInfo.FLAG_ALLOW_BACKUP) != 0 && !isSystem) {
                    val hasCriticalData = permissions.any { perm ->
                        perm.contains("CONTACT") || perm.contains("SMS") ||
                        perm.contains("ACCOUNT") || perm.contains("PASSWORD")
                    }
                    if (hasCriticalData) {
                        riskScore += 15
                        riskReasons.add("Разрешает backup с критическими данными")
                    }
                }

                // 3. Анализ разрешений
                if (dangerousPerms.size > 5) {
                    riskScore += 20
                    riskReasons.add("Много опасных разрешений: ${dangerousPerms.size}")
                }

                if (criticalPerms.isNotEmpty()) {
                    riskScore += criticalPerms.size * 10
                    riskReasons.add("Критические разрешения: ${criticalPerms.joinToString().take(100)}")
                }

                // 4. Проверка SMS/Call разрешений
                val hasSms = permissions.any { it.contains("SMS") }
                val hasCall = permissions.any { it.contains("CALL") }
                val hasInternet = permissions.contains("android.permission.INTERNET")
                if (hasSms && hasInternet && !isSystem) {
                    riskScore += 35
                    riskReasons.add("Доступ к SMS + Интернет = потенциальная утечка/премиум-SMS")
                }
                if (hasCall && hasInternet && !isSystem) {
                    riskScore += 25
                    riskReasons.add("Доступ к звонкам + Интернет")
                }

                // 5. Проверкаoverlay/альтернативых разрешений
                if (permissions.contains("android.permission.SYSTEM_ALERT_WINDOW") && !isSystem) {
                    riskScore += 15
                    riskReasons.add("Overlay window — может использоваться для фишинга")
                }

                // 6. Проверка подписи
                val signatures = Utils.getApkSignature(context, packageName)
                val knownBadSigs = threatDatabase.getKnownBadSignatures()
                for (sig in signatures) {
                    if (sig in knownBadSigs) {
                        riskScore += 50
                        riskReasons.add("Подозрительная подпись: $sig")
                    }
                }

                // 7. Проверка по имени пакета
                for (pattern in Utils.SUSPICIOUS_PACKAGE_PATTERNS) {
                    if (pattern.matches(packageName) || pattern.matches(appName)) {
                        riskScore += 25
                        riskReasons.add("Подозрительное имя: совпадение с паттерном")
                        break
                    }
                }

                // 8. Проверка источника установки
                val installer = try {
                    if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
                        pm.getInstallSourceInfo(packageName).installingPackageName
                    } else {
                        @Suppress("DEPRECATION")
                        pm.getInstallerPackageName(packageName)
                    }
                } catch (e: Exception) { null }

                if (installer == null && !isSystem) {
                    riskScore += 20
                    riskReasons.add("Установлено из неизвестного источника (sideload)")
                }

                // 9. Проверка минимального SDK
                if (pkg.applicationInfo.minSdkVersion < 21 && !isSystem) {
                    riskScore += 5
                    riskReasons.add("Устаревший minSdkVersion (${pkg.applicationInfo.minSdkVersion})")
                }

                // 10. Проверка targetSdkVersion
                if (pkg.applicationInfo.targetSdkVersion < 28 && !isSystem) {
                    riskScore += 10
                    riskReasons.add("Низкий targetSdkVersion (${pkg.applicationInfo.targetSdkVersion}) — обходит новые ограничения")
                }

                // 11. Проверка количество приёмников (broadcast receivers)
                val receivers = pkg.receivers?.size ?: 0
                if (receivers > 20 && !isSystem) {
                    riskScore += 10
                    riskReasons.add("Аномальное количество broadcast receivers ($receivers)")
                }

                // 12. Проверка трекинга
                val trackingPerms = permissions.filter { it in Utils.TRACKING_PERMISSIONS }
                if (trackingPerms.size > 3) {
                    riskScore += 10
                    riskReasons.add("Множественные разрешения трекинга (${trackingPerms.size})")
                }

                // 13. Проверка на данные трекеров в метаданных
                val metaData = appInfo.metaData
                if (metaData != null) {
                    val keys = metaData.keySet()
                    val trackerKeys = keys.filter { key ->
                        key.contains("app_id", ignoreCase = true) ||
                        key.contains("appkey", ignoreCase = true) ||
                        key.contains("flurry", ignoreCase = true) ||
                        key.contains("umeng", ignoreCase = true) ||
                        key.contains("jpush", ignoreCase = true) ||
                        key.contains("getui", ignoreCase = true) ||
                        key.contains("talkingdata", ignoreCase = true)
                    }
                    if (trackerKeys.isNotEmpty()) {
                        riskScore += 5
                        riskReasons.add("Обнаружены ключи трекеров в metadata")
                    }
                }

                // Создание угрозы при высоком риске
                riskScore = riskScore.coerceAtMost(100)
                if (riskScore > 40 && !isSystem) {
                    val threatType = when {
                        hasSms && hasInternet -> ThreatType.SPYWARE
                        riskScore > 80 -> ThreatType.MALWARE
                        trackingPerms.size > 3 -> ThreatType.TRACKER
                        riskScore > 60 -> ThreatType.SUSPICIOUS_FILE
                        else -> ThreatType.PRIVACY_RISK
                    }

                    val severity = when {
                        riskScore > 80 -> ThreatSeverity.CRITICAL
                        riskScore > 60 -> ThreatSeverity.HIGH
                        riskScore > 40 -> ThreatSeverity.MEDIUM
                        else -> ThreatSeverity.LOW
                    }

                    threats.add(ThreatInfo(
                        id = UUID.randomUUID().toString(),
                        type = threatType,
                        severity = severity,
                        name = appName,
                        description = "Обнаружены признаки риска: ${riskReasons.take(3).joinToString("; ")}",
                        filePath = appInfo.sourceDir,
                        packageName = packageName,
                        timestamp = System.currentTimeMillis(),
                        hash = Utils.getFileHash(appInfo.sourceDir),
                        fileSize = File(appInfo.sourceDir).length(),
                        action = when {
                            riskScore > 80 -> ThreatAction.DELETE
                            riskScore > 60 -> ThreatAction.QUARANTINE
                            else -> ThreatAction.WARNING
                        },
                        details = mapOf(
                            "riskScore" to riskScore.toString(),
                            "dangerousPermissions" to dangerousPerms.size.toString(),
                            "criticalPermissions" to criticalPerms.size.toString(),
                            "reasons" to riskReasons.joinToString("|"),
                            "isSystem" to isSystem.toString(),
                            "installer" to (installer ?: "unknown"),
                            "targetSdk" to pkg.applicationInfo.targetSdkVersion.toString()
                        )
                    ))
                }

            } catch (e: Exception) {
                Log.w(TAG, "Error scanning ${pkg.packageName}", e)
            }
        }

        return threats
    }

    /**
     * Сканирование процессов
     */
    private fun scanProcesses(): List<ThreatInfo> {
        val threats = mutableListOf<ThreatInfo>()
        val processEngine = ProcessEngine(context)

        try {
            val processes = processEngine.getRunningProcesses()
            for (process in processes) {
                if (process.riskScore > 50 && !process.isSystem) {
                    val threatType = when {
                        process.riskScore > 80 -> ThreatType.PROCESS_ANOMALY
                        process.riskReasons.any { it.contains("root", ignoreCase = true) } -> ThreatType.EXPLOIT
                        process.riskReasons.any { it.contains("inject", ignoreCase = true) } -> ThreatType.BACKDOOR
                        else -> ThreatType.PROCESS_ANOMALY
                    }

                    threats.add(ThreatInfo(
                        id = UUID.randomUUID().toString(),
                        type = threatType,
                        severity = when {
                            process.riskScore > 80 -> ThreatSeverity.CRITICAL
                            process.riskScore > 60 -> ThreatSeverity.HIGH
                            else -> ThreatSeverity.MEDIUM
                        },
                        name = "Подозрительный процесс: ${process.name}",
                        description = process.riskReasons.joinToString("; "),
                        filePath = "",
                        packageName = process.packageName,
                        timestamp = System.currentTimeMillis(),
                        hash = "",
                        fileSize = 0,
                        action = ThreatAction.MONITOR,
                        details = mapOf(
                            "pid" to process.pid.toString(),
                            "cpu" to process.cpuUsage.toString(),
                            "memory" to process.memoryUsage.toString(),
                            "threads" to process.threads.toString(),
                            "reasons" to process.riskReasons.joinToString("|")
                        )
                    ))
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Process scan error", e)
        }

        return threats
    }

    /**
     * Сканирование файловой системы
     */
    private suspend fun scanFileSystem(onFile: (Long, String) -> Unit): List<ThreatInfo> {
        val threats = mutableListOf<ThreatInfo>()
        val scanPaths = listOf(
            "/sdcard",
            "/storage/emulated/0",
            "/data/local/tmp"
        )

        var count = 0L
        for (path in scanPaths) {
            val dir = File(path)
            if (dir.exists() && dir.canRead()) {
                threats.addAll(scanDirectory(dir, depth = 10) { c, p ->
                    count += c
                    onFile(count, p)
                })
            }
        }
        return threats
    }

    /**
     * Рекурсивное сканирование директории
     */
    private fun scanDirectory(
        directory: File,
        depth: Int = 5,
        onFile: (Long, String) -> Unit
    ): List<ThreatInfo> {
        val threats = mutableListOf<ThreatInfo>()
        if (depth <= 0 || !directory.exists() || !directory.canRead()) return threats

        try {
            val files = directory.listFiles() ?: return threats
            for (file in files) {
                try {
                    onFile(1, file.absolutePath)

                    if (file.isDirectory) {
                        threats.addAll(scanDirectory(file, depth - 1, onFile))
                    } else {
                        val threat = analyzeFile(file)
                        if (threat != null) {
                            threats.add(threat)
                        }
                    }
                } catch (e: Exception) {
                    // Skip inaccessible files
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Cannot read directory: ${directory.absolutePath}", e)
        }

        return threats
    }

    /**
     * Анализ отдельного файла
     */
    private fun analyzeFile(file: File): ThreatInfo? {
        val fileName = file.name
        val filePath = file.absolutePath
        var riskScore = 0
        val riskReasons = mutableListOf<String>()

        // 1. Проверка расширения
        val suspiciousExtensions = setOf("apk", "dex", "jar", "exe", "dll", "bat", "cmd", "ps1", "vbs", "so")
        val ext = fileName.substringAfterLast('.', "")
        if (ext.lowercase() in suspiciousExtensions) {
            riskScore += 30
            riskReasons.add("Подозрительное расширение: .$ext")

            // Дополнительная проверка APK
            if (ext.equals("apk", ignoreCase = true)) {
                val hash = Utils.getFileMd5(filePath)
                if (threatDatabase.isKnownMalwareHash(hash)) {
                    riskScore += 80
                    riskReasons.add("Хеш совпадает с известным malware: $hash")
                }

                // Проверка размера (слишком маленький APK может быть загрузчиком)
                if (file.length() < 50000 && ext.equals("apk", ignoreCase = true)) {
                    riskScore += 25
                    riskReasons.add("Очень маленький APK (${file.length()} байт) — возможный dropper")
                }
            }

            // Проверка DEX файлов вне стандартных путей
            if (ext.equals("dex", ignoreCase = true)) {
                val standardPaths = listOf("dalvik-cache", "dex", "oat")
                if (standardPaths.none { filePath.contains(it) }) {
                    riskScore += 50
                    riskReasons.add("DEX файл в нестандартном месте")
                }
            }

            // Проверка SO файлов
            if (ext.equals("so", ignoreCase = true)) {
                val standardPaths = listOf("lib", "jni")
                if (standardPaths.none { filePath.contains(it) }) {
                    riskScore += 35
                    riskReasons.add("SO библиотека в нестандартном месте")
                }
            }
        }

        // 2. Проверка скрытых файлов
        if (fileName.startsWith(".") && fileName.length > 1) {
            riskScore += 15
            riskReasons.add("Скрытый файл")
        }

        // 3. Проверка подозрительных имён
        val suspiciousNames = listOf("payload", "exploit", "hack", "crack", "keygen",
            "patch", "inject", "hook", "root", "su", "busybox", "supersu")
        for (pattern in suspiciousNames) {
            if (fileName.contains(pattern, ignoreCase = true)) {
                riskScore += 20
                riskReasons.add("Подозрительное имя файла: содержит '$pattern'")
                break
            }
        }

        // 4. Проверка на двойные расширения
        val dotCount = fileName.count { it == '.' }
        if (dotCount > 1) {
            val parts = fileName.split(".")
            if (parts.size >= 3 && parts[parts.size - 2].lowercase() in suspiciousExtensions) {
                riskScore += 30
                riskReasons.add("Двойное расширение — возможно маскировка")
            }
        }

        // 5. Проверка размеров
        if (file.length() == 0L) {
            return null // Пустые файлы не анализируем
        }

        // 6. Проверка hash
        val md5 = Utils.getFileMd5(filePath)
        if (md5.isNotEmpty() && threatDatabase.isKnownMalwareHash(md5)) {
            riskScore += 80
            riskReasons.add("Известный вредоносный файл (hash: ${md5.take(16)}...)")
        }

        // 7. Проверка исполняемых файлов в нестандартных местах
        if (file.canExecute() && !file.isDirectory) {
            val executablePaths = listOf("bin", "xbin", "sbin", "system/bin")
            if (executablePaths.none { filePath.contains(it) }) {
                riskScore += 10
                riskReasons.add("Исполняемый файл в нестандартном месте")
            }
        }

        // Создание угрозы при достаточном риске
        return if (riskScore >= 30) {
            ThreatInfo(
                id = UUID.randomUUID().toString(),
                type = when {
                    riskScore > 80 -> ThreatType.MALWARE
                    riskScore > 60 -> ThreatType.TROJAN
                    ext.equals("apk", ignoreCase = true) -> ThreatType.SUSPICIOUS_FILE
                    else -> ThreatType.SUSPICIOUS_FILE
                },
                severity = when {
                    riskScore > 80 -> ThreatSeverity.CRITICAL
                    riskScore > 60 -> ThreatSeverity.HIGH
                    riskScore > 40 -> ThreatSeverity.MEDIUM
                    else -> ThreatSeverity.LOW
                },
                name = "Подозрительный файл: $fileName",
                description = riskReasons.joinToString("; "),
                filePath = filePath,
                packageName = "",
                timestamp = System.currentTimeMillis(),
                hash = md5,
                fileSize = file.length(),
                action = when {
                    riskScore > 80 -> ThreatAction.QUARANTINE
                    riskScore > 60 -> ThreatAction.WARNING
                    else -> ThreatAction.WARNING
                },
                details = mapOf(
                    "riskScore" to riskScore.toString(),
                    "reasons" to riskReasons.joinToString("|"),
                    "extension" to ext,
                    "size" to file.length().toString(),
                    "executable" to file.canExecute().toString()
                )
            )
        } else null
    }

    /**
     * Сетевой анализ
     */
    private fun scanNetwork(): List<ThreatInfo> {
        val threats = mutableListOf<ThreatInfo>()
        val networkEngine = NetworkEngine(context)

        try {
            val connections = networkEngine.getActiveConnections()
            for (conn in connections) {
                if (conn.isSuspicious) {
                    threats.add(ThreatInfo(
                        id = UUID.randomUUID().toString(),
                        type = ThreatType.NETWORK_ANOMALY,
                        severity = if (conn.remotePort in Utils.SUSPICIOUS_PORTS)
                            ThreatSeverity.HIGH else ThreatSeverity.MEDIUM,
                        name = "Подозрительное подключение: ${conn.appName}",
                        description = conn.riskReasons.joinToString("; "),
                        filePath = "",
                        packageName = conn.packageName,
                        timestamp = System.currentTimeMillis(),
                        hash = "",
                        fileSize = 0,
                        action = ThreatAction.BLOCK,
                        details = mapOf(
                            "remoteAddress" to conn.remoteAddress,
                            "remotePort" to conn.remotePort.toString(),
                            "protocol" to conn.protocol,
                            "state" to conn.state,
                            "reasons" to conn.riskReasons.joinToString("|")
                        )
                    ))
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Network scan error", e)
        }

        return threats
    }

    /**
     * Проверка автозапусков
     */
    private fun scanAutostarts(): List<ThreatInfo> {
        val threats = mutableListOf<ThreatInfo>()
        val autostartEngine = AutostartEngine(context)

        try {
            val autostarts = autostartEngine.getAutostartApps()
            for (item in autostarts) {
                if (item.riskLevel == RiskLevel.HIGH || item.riskLevel == RiskLevel.CRITICAL) {
                    threats.add(ThreatInfo(
                        id = UUID.randomUUID().toString(),
                        type = ThreatType.AUTOSTART_ABUSE,
                        severity = when (item.riskLevel) {
                            RiskLevel.CRITICAL -> ThreatSeverity.CRITICAL
                            RiskLevel.HIGH -> ThreatSeverity.HIGH
                            else -> ThreatSeverity.MEDIUM
                        },
                        name = "Подозрительный автозапуск: ${item.appName}",
                        description = "${item.appName} запускается при: ${item.category.name}",
                        filePath = "",
                        packageName = item.packageName,
                        timestamp = System.currentTimeMillis(),
                        hash = "",
                        fileSize = 0,
                        action = ThreatAction.DISABLE,
                        details = mapOf(
                            "receiver" to item.receiverName,
                            "action" to item.action,
                            "category" to item.category.name,
                            "priority" to item.priority.toString()
                        )
                    ))
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Autostart scan error", e)
        }

        return threats
    }
}
