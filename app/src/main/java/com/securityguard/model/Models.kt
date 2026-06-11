package com.securityguard.model

import android.graphics.drawable.Drawable
import android.os.Parcelable
import kotlinx.parcelize.Parcelize

/**
 * Модель установленного приложения
 */
data class AppInfo(
    val packageName: String,
    val appName: String,
    val versionName: String,
    val versionCode: Long,
    val installTime: Long,
    val updateTime: Long,
    val apkPath: String,
    val dataSize: Long,
    val cacheSize: Long,
    val isSystemApp: Boolean,
    val isEnabled: Boolean,
    val hasAutostart: Boolean,
    val targetSdkVersion: Int,
    val minSdkVersion: Int,
    val uid: Int,
    val icon: Drawable?,
    val permissions: List<String>,
    val dangerousPermissions: List<String>,
    val riskScore: Int, // 0-100
    val riskLevel: RiskLevel,
    val signatures: List<String>,
    val isDebuggable: Boolean,
    val allowsBackup: Boolean,
    val hasAds: Boolean,
    val hasTracking: Boolean,
    val categories: Set<String>
)

enum class RiskLevel {
    SAFE,        // 0-20
    LOW,         // 21-40
    MEDIUM,      // 41-60
    HIGH,        // 61-80
    CRITICAL     // 81-100
}

/**
 * Модель процесса
 */
data class ProcessInfo(
    val pid: Int,
    val ppid: Int,
    val name: String,
    val packageName: String,
    val uid: Int,
    val cpuUsage: Float,
    val memoryUsage: Long,
    val memoryPercent: Float,
    val threads: Int,
    val state: String,
    val startTime: Long,
    val isSystem: Boolean,
    val isForeground: Boolean,
    val isOpenFiles: Int,
    val networkConnections: Int,
    val riskScore: Int,
    val riskReasons: List<String>
)

/**
 * Модель сетевого соединения
 */
data class NetworkConnection(
    val protocol: String,
    val localAddress: String,
    val localPort: Int,
    val remoteAddress: String,
    val remotePort: Int,
    val state: String,
    val uid: Int,
    val appName: String,
    val packageName: String,
    val isEstablished: Boolean,
    val isSuspicious: Boolean,
    val riskReasons: List<String>
)

/**
 * Модель угрозы / детекта
 */
@Parcelize
data class ThreatInfo(
    val id: String,
    val type: ThreatType,
    val severity: ThreatSeverity,
    val name: String,
    val description: String,
    val filePath: String,
    val packageName: String,
    val timestamp: Long,
    val hash: String,
    val fileSize: Long,
    val action: ThreatAction,
    val details: Map<String, String>
) : Parcelable

enum class ThreatType {
    MALWARE,
    SUSPICIOUS_FILE,
    DANGEROUS_PERMISSION,
    AUTOSTART_ABUSE,
    NETWORK_ANOMALY,
    PROCESS_ANOMALY,
    PRIVACY_RISK,
    ADWARE,
    SPYWARE,
    TROJAN,
    RANSOMWARE,
    PHISHING,
    EXPLOIT,
    BACKDOOR,
    TRACKER
}

enum class ThreatSeverity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}

enum class ThreatAction {
    NONE,
    WARNING,
    QUARANTINE,
    DELETE,
    DISABLE,
    BLOCK,
    MONITOR
}

/**
 * Результат сканирования
 */
@Parcelize
data class ScanResult(
    val id: String,
    val scanType: ScanType,
    val startTime: Long,
    val endTime: Long,
    val filesScanned: Long,
    val appsScanned: Int,
    val processesScanned: Int,
    val threatsFound: List<ThreatInfo>,
    val totalSize: Long,
    val isCompleted: Boolean
) : Parcelable

enum class ScanType {
    QUICK,          // Быстрое сканирование (приложения + критические папки)
    FULL,           // Полное сканирование (весь накопитель)
    APP,            // Сканирование конкретного приложения
    MEMORY,         // Оперативная память
    CUSTOM,         // Пользовательский путь
    REALTIME        // Мониторинг в реальном времени
}

/**
 * Модель автозапуска
 */
data class AutostartItem(
    val packageName: String,
    val appName: String,
    val icon: Drawable?,
    val receiverName: String,
    val action: String,
    val priority: Int,
    val isSystemApp: Boolean,
    val isEnabled: Boolean,
    val riskLevel: RiskLevel,
    val category: AutostartCategory
)

enum class AutostartCategory {
    BOOT,           // При загрузке
    USER_PRESENT,   // При разблокировке
    NETWORK,        // При подключении к сети
    MEDIA,          // При подключении медиа
    SMS,            // При получении SMS
    CALL,           // При звонке
    BATTERY,        // При изменении заряда
    LOCATION,       // При изменении местоположения
    SCREEN,         // При включении/выключении экрана
    CUSTOM          // Пользовательские события
}

/**
 * Security Score компоненты
 */
data class SecurityScore(
    val overallScore: Int,      // 0-100
    val malwareScore: Int,      // 0-100
    val permissionScore: Int,   // 0-100
    val networkScore: Int,      // 0-100
    val privacyScore: Int,      // 0-100
    val autostartScore: Int,    // 0-100
    val systemScore: Int,       // 0-100
    val details: SecurityDetails
)

data class SecurityDetails(
    val installedApps: Int,
    val systemApps: Int,
    val dangerousApps: Int,
    val criticalPermissions: Int,
    val autostartApps: Int,
    val activeConnections: Int,
    val runningProcesses: Int,
    val suspiciousProcesses: Int,
    val threats: Int,
    val lastScanTime: Long
)

/**
 * Quarantine item
 */
@Parcelize
data class QuarantineItem(
    val id: String,
    val originalPath: String,
    val quarantinePath: String,
    val threatInfo: ThreatInfo,
    val quarantineTime: Long,
    val originalHash: String
) : Parcelable
