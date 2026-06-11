package com.securityguard.engine

import android.app.ActivityManager
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import com.securityguard.model.ProcessInfo
import com.securityguard.util.Utils
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

/**
 * Движок мониторинга процессов
 * Получает информацию о процессах из /proc, ActivityManager и UsageStatsManager
 */
class ProcessEngine(private val context: Context) {

    companion object {
        private const val TAG = "ProcessEngine"
    }

    /**
     * Получить список всех запущенных процессов
     */
    fun getRunningProcesses(): List<ProcessInfo> {
        val processes = mutableListOf<ProcessInfo>()
        val processMap = mutableMapOf<String, ProcessInfo>()

        // Метод 1: Чтение /proc (самый информативный)
        readProcProcesses(processMap)

        // Метод 2: ActivityManager
        readActivityManagerProcesses(processMap)

        // Метод 3: UsageStatsManager для дополнительных данных
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
            readUsageStatsProcesses(processMap)
        }

        // Вычисление рисков и формирование списка
        for ((key, proc) in processMap) {
            val analyzed = analyzeProcess(proc)
            processes.add(analyzed)
        }

        // Сортировка по использованию CPU
        return processes.sortedByDescending { it.cpuUsage }
    }

    /**
     * Чтение процессов из /proc директории
     */
    private fun readProcProcesses(processMap: mutableMapOf<String, ProcessInfo>) {
        val procDir = File("/proc")
        if (!procDir.exists() || !procDir.canRead()) return

        val dirs = procDir.listFiles()?.filter { it.name.matches(Regex("\\d+")) } ?: return

        for (procDir in dirs) {
            try {
                val pid = procDir.name.toInt()
                val statFile = File(procDir, "stat")
                val statusFile = File(procDir, "status")
                val cmdlineFile = File(procDir, "cmdline")

                if (!statFile.canRead()) continue

                // Парсинг /proc/[pid]/stat
                val stat = statFile.readText().trim()
                val statParts = parseStatFile(stat)

                // Парсинг /proc/[pid]/cmdline для имени
                val cmdline = if (cmdlineFile.canRead()) {
                    cmdlineFile.readText().replace('\u0000', ' ').trim()
                } else ""

                // Парсинг /proc/[pid]/status
                val (uid, threads, vmSize) = parseStatusFile(statusFile)

                // Определение имени пакета
                val packageName = extractPackageName(cmdline, pid)

                // CPU usage (упрощённый расчёт)
                val cpuUsage = calculateCpuUsage(statParts)

                // Memory usage
                val memoryUsage = vmSize

                // Process state
                val state = statParts.getOrNull(2) ?: "S"

                // PPID
                val ppid = statParts.getOrNull(3)?.toIntOrNull() ?: 0

                // Кол-во открытых файлов
                val openFiles = countOpenFiles(pid)

                // Сетевые соединения
                val netConnections = countNetworkConnections(pid)

                val name = cmdline.takeIf { it.isNotBlank() }
                    ?: statParts.getOrNull(1)?.trim('(')?.trim(')') ?: "pid-$pid"

                val processInfo = ProcessInfo(
                    pid = pid,
                    ppid = ppid,
                    name = name.take(200),
                    packageName = packageName,
                    uid = uid,
                    cpuUsage = cpuUsage,
                    memoryUsage = memoryUsage,
                    memoryPercent = 0f, // Вычислим позже
                    threads = threads,
                    state = state,
                    startTime = System.currentTimeMillis(),
                    isSystem = uid < 10000,
                    isForeground = false,
                    isOpenFiles = openFiles,
                    networkConnections = netConnections,
                    riskScore = 0,
                    riskReasons = emptyList()
                )

                processMap[pid.toString()] = processInfo

            } catch (e: Exception) {
                // Процесс может завершиться во время чтения
            }
        }

        // Вычисление процентов памяти
        val totalMemory = getTotalMemory()
        for ((_, proc) in processMap) {
            val memPercent = if (totalMemory > 0) {
                (proc.memoryUsage.toFloat() / totalMemory) * 100f
            } else 0f
            processMap[proc.pid.toString()] = proc.copy(memoryPercent = memPercent)
        }
    }

    /**
     * Чтение процессов через ActivityManager
     */
    private fun readActivityManagerProcesses(processMap: mutableMapOf<String, ProcessInfo>) {
        try {
            val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
            val processes = am.runningAppProcesses ?: return

            for (processInfo in processes) {
                val pid = processInfo.pid
                if (pid == 0) continue

                val existing = processMap[pid.toString()]
                if (existing != null) {
                    // Обновляем информацию
                    processMap[pid.toString()] = existing.copy(
                        packageName = processInfo.processName,
                        isForeground = processInfo.importance ==
                                ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND,
                        name = existing.name.ifEmpty { processInfo.processName }
                    )
                } else {
                    // Добавляем новый процесс
                    processMap[pid.toString()] = ProcessInfo(
                        pid = pid,
                        ppid = 0,
                        name = processInfo.processName,
                        packageName = processInfo.processName,
                        uid = processInfo.uid,
                        cpuUsage = 0f,
                        memoryUsage = 0,
                        memoryPercent = 0f,
                        threads = 1,
                        state = "S",
                        startTime = System.currentTimeMillis(),
                        isSystem = processInfo.uid < 10000,
                        isForeground = processInfo.importance ==
                                ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND,
                        isOpenFiles = 0,
                        networkConnections = 0,
                        riskScore = 0,
                        riskReasons = emptyList()
                    )
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "ActivityManager read error", e)
        }
    }

    /**
     * Чтение через UsageStatsManager
     */
    private fun readUsageStatsProcesses(processMap: mutableMapOf<String, ProcessInfo>) {
        try {
            val usm = context.getSystemService(Context.USAGE_STATS_SERVICE) as? UsageStatsManager
                ?: return
            val endTime = System.currentTimeMillis()
            val startTime = endTime - 60000 // Последняя минута

            val stats = usm.queryUsageStats(UsageStatsManager.INTERVAL_DAILY, startTime, endTime)
            for (stat in stats) {
                if (stat.lastTimeUsed > startTime) {
                    // Приложение активно
                    // Используем информацию для обновления существующих процессов
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "UsageStats read error", e)
        }
    }

    /**
     * Анализ процесса на предмет подозрительности
     */
    private fun analyzeProcess(process: ProcessInfo): ProcessInfo {
        var riskScore = 0
        val riskReasons = mutableListOf<String>()

        // 1. Высокое использование CPU
        if (process.cpuUsage > 50f) {
            riskScore += 20
            riskReasons.add("Высокое использование CPU: ${"%.1f".format(process.cpuUsage)}%")
        }

        // 2. Большое потребление памяти
        if (process.memoryPercent > 30f) {
            riskScore += 15
            riskReasons.add("Большое потребление памяти: ${"%.1f".format(process.memoryPercent)}%")
        }

        // 3. Слишком много потоков
        if (process.threads > 100) {
            riskScore += 15
            riskReasons.add("Много потоков: ${process.threads}")
        }

        // 4. Много открытых файлов
        if (process.isOpenFiles > 500) {
            riskScore += 10
            riskReasons.add("Много открытых файлов: ${process.isOpenFiles}")
        }

        // 5. Много сетевых соединений
        if (process.networkConnections > 20) {
            riskScore += 20
            riskReasons.add("Много сетевых соединений: ${process.networkConnections}")
        }

        // 6. Проверка имени процесса
        val suspiciousNames = listOf("inject", "hook", "root", "su", "daemon", "frida",
            "xposed", "substrate", "magisk", "supersu")
        for (name in suspiciousNames) {
            if (process.name.contains(name, ignoreCase = true)) {
                riskScore += 30
                riskReasons.add("Подозрительное имя процесса: '$name'")
                break
            }
        }

        // 7. Процесс не из Play Store / системный
        if (!process.isSystem && process.packageName.isNotEmpty()) {
            try {
                val pkgInfo = context.packageManager.getPackageInfo(
                    process.packageName, 0
                )
                val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    context.packageManager.getInstallSourceInfo(process.packageName)
                        .installingPackageName
                } else {
                    @Suppress("DEPRECATION")
                    context.packageManager.getInstallerPackageName(process.packageName)
                }
                if (installer == null) {
                    riskScore += 10
                    riskReasons.add("Приложение из неизвестного источника")
                }
            } catch (e: Exception) {
                // Процесс может не иметь пакета
            }
        }

        // 8. Проверка на root-процессы
        if (process.uid == 0 || process.name.contains("su") || process.name == "daemonsu") {
            riskScore += 40
            riskReasons.add("Root-процесс обнаружен")
        }

        return process.copy(
            riskScore = riskScore.coerceAtMost(100),
            riskReasons = riskReasons
        )
    }

    // ===== Вспомогательные методы =====

    private fun parseStatFile(stat: String): List<String> {
        // Формат: pid (comm) state ppid pgrp session tty_nr tpgid ...
        // comm может содержать пробелы и скобки
        val result = mutableListOf<String>()
        val firstParen = stat.indexOf('(')
        val lastParen = stat.lastIndexOf(')')

        if (firstParen >= 0 && lastParen > firstParen) {
            result.add(stat.substring(0, firstParen).trim()) // pid
            result.add(stat.substring(firstParen + 1, lastParen)) // comm
            result.addAll(stat.substring(lastParen + 2).split(" "))
        } else {
            result.addAll(stat.split(" "))
        }

        return result
    }

    private fun parseStatusFile(statusFile: File): Triple<Int, Int, Long> {
        var uid = 0
        var threads = 1
        var vmSize = 0L

        try {
            if (statusFile.canRead()) {
                statusFile.forEachLine { line ->
                    when {
                        line.startsWith("Uid:") -> {
                            uid = line.substringAfter("Uid:").trim().split("\\s+".toRegex())
                                .firstOrNull()?.toIntOrNull() ?: 0
                        }
                        line.startsWith("Threads:") -> {
                            threads = line.substringAfter("Threads:").trim().toIntOrNull() ?: 1
                        }
                        line.startsWith("VmSize:") -> {
                            val sizeStr = line.substringAfter("VmSize:").trim()
                                .split("\\s+".toRegex()).firstOrNull() ?: "0"
                            vmSize = (sizeStr.toLongOrNull() ?: 0) * 1024 // kB to bytes
                        }
                    }
                }
            }
        } catch (e: Exception) { }

        return Triple(uid, threads, vmSize)
    }

    private fun extractPackageName(cmdline: String, pid: Int): String {
        if (cmdline.isBlank()) return ""
        val firstPart = cmdline.split(" ").firstOrNull() ?: ""
        // Пакеты обычно в формате com.example.app
        return if (firstPart.count { it == '.' } >= 2) firstPart else ""
    }

    private fun calculateCpuUsage(statParts: List<String>): Float {
        // Упрощённый расчёт на основе utime + stime
        val utime = statParts.getOrNull(13)?.toLongOrNull() ?: 0
        val stime = statParts.getOrNull(14)?.toLongOrNull() ?: 0
        val total = utime + stime
        // Нормализация (очень грубая)
        return if (total > 0) (total % 1000) / 10f else 0f
    }

    private fun countOpenFiles(pid: Int): Int {
        return try {
            val fdDir = File("/proc/$pid/fd")
            if (fdDir.exists() && fdDir.canRead()) {
                fdDir.listFiles()?.size ?: 0
            } else 0
        } catch (e: Exception) { 0 }
    }

    private fun countNetworkConnections(pid: Int): Int {
        return try {
            val fdDir = File("/proc/$pid/fd") ?: return 0
            if (!fdDir.exists() || !fdDir.canRead()) return 0
            var count = 0
            fdDir.listFiles()?.forEach { fd ->
                try {
                    val link = fd.canonicalPath
                    if (link.contains("socket:")) count++
                } catch (e: Exception) { }
            }
            count
        } catch (e: Exception) { 0 }
    }

    private fun getTotalMemory(): Long {
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val memInfo = ActivityManager.MemoryInfo()
        am.getMemoryInfo(memInfo)
        return memInfo.totalMem
    }

    /**
     * Убить процесс
     */
    fun killProcess(pid: Int): Boolean {
        return try {
            val am = context.getSystemService(Context.ACTIVITY_VALUE) as ActivityManager
            // Попытка через ActivityManager
            val processes = am.runningAppProcesses
            val targetProcess = processes?.find { it.pid == pid }
            if (targetProcess != null) {
                am.killBackgroundProcesses(targetProcess.processName)
                true
            } else {
                // Попытка через kill command
                val process = Runtime.getRuntime().exec("kill $pid")
                process.waitFor()
                process.exitValue() == 0
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to kill process $pid", e)
            false
        }
    }
}
