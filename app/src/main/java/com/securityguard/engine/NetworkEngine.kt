package com.securityguard.engine

import android.content.Context
import android.util.Log
import com.securityguard.model.NetworkConnection
import com.securityguard.util.Utils
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

/**
 * Движок мониторинга сети
 * Читает /proc/net для получения информации о сетевых соединениях
 */
class NetworkEngine(private val context: Context) {

    companion object {
        private const val TAG = "NetworkEngine"
    }

    /**
     * Получить все активные сетевые соединения
     */
    fun getActiveConnections(): List<NetworkConnection> {
        val connections = mutableListOf<NetworkConnection>()

        // Читаем TCP соединения
        connections.addAll(readConnections("/proc/net/tcp", "TCP"))
        connections.addAll(readConnections("/proc/net/tcp6", "TCP6"))
        connections.addAll(readConnections("/proc/net/udp", "UDP"))
        connections.addAll(readConnections("/proc/net/udp6", "UDP6"))

        // Анализируем каждое соединение
        return connections.map { analyzeConnection(it) }
    }

    /**
     * Чтение соединений из /proc/net/
     */
    private fun readConnections(path: String, protocol: String): List<NetworkConnection> {
        val connections = mutableListOf<NetworkConnection>()
        try {
            val file = File(path)
            if (!file.exists() || !file.canRead()) return connections

            file.forEachLine { line ->
                try {
                    val trimmed = line.trim()
                    if (trimmed.isEmpty() || trimmed.startsWith("sl") || trimmed.startsWith("Sk")) {
                        return@forEachLine // Пропускаем заголовок
                    }

                    val parts = trimmed.split("\\s+".toRegex())
                    if (parts.size < 10) return@forEachLine

                    // Парсинг адресов
                    val local = parts[1]
                    val remote = parts[2]
                    val state = parts[3]
                    val uid = parts[7].toIntOrNull() ?: 0

                    val (localAddr, localPort) = parseAddress(local, protocol.contains("6"))
                    val (remoteAddr, remotePort) = parseAddress(remote, protocol.contains("6"))

                    // Определяем имя приложения
                    val appName = getAppNameForUid(uid)
                    val packageName = getPackageNameForUid(uid)

                    val conn = NetworkConnection(
                        protocol = protocol,
                        localAddress = localAddr,
                        localPort = localPort,
                        remoteAddress = remoteAddr,
                        remotePort = remotePort,
                        state = parseState(state.toIntOrNull(16) ?: 0, protocol),
                        uid = uid,
                        appName = appName,
                        packageName = packageName,
                        isEstablished = state.toIntOrNull(16) == 1, // ESTABLISHED
                        isSuspicious = false,
                        riskReasons = emptyList()
                    )
                    connections.add(conn)

                } catch (e: Exception) {
                    // Пропускаем строки с ошибками парсинга
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Error reading $path", e)
        }

        return connections
    }

    /**
     * Анализ соединения на подозрительность
     */
    private fun analyzeConnection(conn: NetworkConnection): NetworkConnection {
        var isSuspicious = false
        val riskReasons = mutableListOf<String>()

        // 1. Проверка на подозрительные порты
        if (conn.remotePort in Utils.SUSPICIOUS_PORTS) {
            isSuspicious = true
            riskReasons.add("Подозрительный порт: ${conn.remotePort}")
        }

        // 2. Проверка на внешние соединения
        if (!Utils.isPrivateIp(conn.remoteAddress) &&
            conn.remoteAddress != "0.0.0.0" &&
            conn.remoteAddress != "::" &&
            conn.remotePort != 0) {

            // Соединение с внешним IP
            if (conn.remotePort in setOf(4444, 5555, 1337, 31337, 12345, 27374)) {
                isSuspicious = true
                riskReasons.add("C2-порт обнаружен: ${conn.remotePort}")
            }

            // Проверка на Tor
            if (conn.remotePort == 9050 || conn.remotePort == 9051) {
                isSuspicious = true
                riskReasons.add("Tor-соединение обнаружено")
            }
        }

        // 3. Много одновременных соединений от одного приложения
        // (определяется на уровне вызывающего кода)

        // 4. Системные приложения с внешними соединениями
        if (conn.uid < 10000 && !Utils.isPrivateIp(conn.remoteAddress)) {
            // Системные процессы обычно не должны иметь много внешних соединений
            // Но Google Play Services и др. имеют, так что это не критично
        }

        // 5. Неизвестные приложения с сетевой активностью
        if (conn.appName == "Unknown ($${conn.uid})" && conn.isEstablished) {
            isSuspicious = true
            riskReasons.add("Неизвестное приложение с активным соединением")
        }

        // 6. DNS на нестандартных портах
        if (conn.remotePort == 53 && conn.localPort != 0) {
            // DNS запрос - нормальное поведение
        }

        // 7. Проверка на подозрительные IP-адреса
        if (conn.remoteAddress.matches(Regex("^[0-9a-fA-F:]+$")) && conn.remoteAddress != "::1") {
            // IPv6 соединение
        }

        return conn.copy(
            isSuspicious = isSuspicious,
            riskReasons = riskReasons
        )
    }

    /**
     * Парсинг адреса из hex формата /proc/net
     */
    private fun parseAddress(hex: String, isIPv6: Boolean): Pair<String, Int> {
        try {
            val parts = hex.split(":")
            if (parts.size != 2) return Pair("0.0.0.0", 0)

            val port = parts[1].toIntOrNull(16) ?: 0

            if (isIPv6) {
                // IPv6 адрес
                val addrHex = parts[0]
                val addr = StringBuilder()
                for (i in 0 until addrHex.length step 4) {
                    if (i > 0) addr.append(":")
                    val seg = addrHex.substring(i, minOf(i + 4, addrHex.length))
                    addr.append(seg)
                }
                return Pair(addr.toString(), port)
            } else {
                // IPv4 адрес (little-endian!)
                val addrHex = parts[0]
                if (addrHex.length == 8) {
                    val b1 = addrHex.substring(6, 8).toInt(16)
                    val b2 = addrHex.substring(4, 6).toInt(16)
                    val b3 = addrHex.substring(2, 4).toInt(16)
                    val b4 = addrHex.substring(0, 2).toInt(16)
                    return Pair("$b1.$b2.$b3.$b4", port)
                }
            }
        } catch (e: Exception) { }

        return Pair("0.0.0.0", 0)
    }

    /**
     * Парсинг состояния TCP соединения
     */
    private fun parseState(state: Int, protocol: String): String {
        return when (state) {
            0x01 -> "ESTABLISHED"
            0x02 -> "SYN_SENT"
            0x03 -> "SYN_RECV"
            0x04 -> "FIN_WAIT1"
            0x05 -> "FIN_WAIT2"
            0x06 -> "TIME_WAIT"
            0x07 -> "CLOSE"
            0x08 -> "CLOSE_WAIT"
            0x09 -> "LAST_ACK"
            0x0A -> "LISTEN"
            0x0B -> "CLOSING"
            else -> "UNKNOWN($state)"
        }
    }

    /**
     * Получить имя приложения по UID
     */
    private fun getAppNameForUid(uid: Int): String {
        try {
            val pm = context.packageManager
            val packages = pm.getPackagesForUid(uid)
            if (packages != null && packages.isNotEmpty()) {
                val pkgName = packages[0]
                return try {
                    val appInfo = pm.getApplicationInfo(pkgName, 0)
                    pm.getApplicationLabel(appInfo).toString()
                } catch (e: Exception) {
                    pkgName
                }
            }
        } catch (e: Exception) { }
        return "Unknown ($uid)"
    }

    /**
     * Получить имя пакета по UID
     */
    private fun getPackageNameForUid(uid: Int): String {
        try {
            val packages = context.packageManager.getPackagesForUid(uid)
            return packages?.firstOrNull() ?: ""
        } catch (e: Exception) { }
        return ""
    }

    /**
     * Получить статистику сети
     */
    fun getNetworkStats(): NetworkStats {
        val connections = getActiveConnections()
        val established = connections.count { it.isEstablished }
        val listening = connections.count { it.state == "LISTEN" }
        val suspicious = connections.count { it.isSuspicious }
        val uniqueApps = connections.map { it.packageName }.distinct().size

        return NetworkStats(
            totalConnections = connections.size,
            establishedConnections = established,
            listeningConnections = listening,
            suspiciousConnections = suspicious,
            uniqueApps = uniqueApps,
            connections = connections
        )
    }

    data class NetworkStats(
        val totalConnections: Int,
        val establishedConnections: Int,
        val listeningConnections: Int,
        val suspiciousConnections: Int,
        val uniqueApps: Int,
        val connections: List<NetworkConnection>
    )
}
