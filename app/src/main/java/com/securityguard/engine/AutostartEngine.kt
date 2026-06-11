package com.securityguard.engine

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ResolveInfo
import android.util.Log
import com.securityguard.model.*
import com.securityguard.util.Utils

/**
 * Движок анализа автозапусков
 * Обнаруживает приложения, которые запускаются автоматически при различных событиях
 */
class AutostartEngine(private val context: Context) {

    companion object {
        private const val TAG = "AutostartEngine"

        // Все действия, при которых приложения могут автоматически запускаться
        val BOOT_ACTIONS = mapOf(
            AutostartCategory.BOOT to listOf(
                Intent.ACTION_BOOT_COMPLETED,
                "android.intent.action.QUICKBOOT_POWERON",
                "com.htc.intent.action.QUICKBOOT_POWERON",
                Intent.ACTION_LOCKED_BOOT_COMPLETED
            ),
            AutostartCategory.USER_PRESENT to listOf(
                Intent.ACTION_USER_PRESENT,
                Intent.ACTION_USER_UNLOCKED
            ),
            AutostartCategory.NETWORK to listOf(
                "android.net.conn.CONNECTIVITY_CHANGE",
                "android.net.wifi.WIFI_STATE_CHANGED",
                "android.net.wifi.STATE_CHANGE",
                "android.net.wifi.SCAN_RESULTS",
                "android.net.wifi.supplicant.STATE_CHANGE"
            ),
            AutostartCategory.MEDIA to listOf(
                Intent.ACTION_MEDIA_MOUNTED,
                Intent.ACTION_MEDIA_SCANNER_SCAN_FILE,
                Intent.ACTION_MEDIA_EJECT,
                "android.intent.action.MEDIA_SCANNER_FINISHED"
            ),
            AutostartCategory.SMS to listOf(
                "android.provider.Telephony.SMS_RECEIVED",
                "android.provider.Telephony.SMS_DELIVER",
                "android.provider.Telephony.WAP_PUSH_RECEIVED",
                "android.provider.Telephony.SMS_SENT"
            ),
            AutostartCategory.CALL to listOf(
                "android.intent.action.PHONE_STATE",
                "android.intent.action.NEW_OUTGOING_CALL",
                "android.intent.action.PHONE_RINGING"
            ),
            AutostartCategory.BATTERY to listOf(
                Intent.ACTION_BATTERY_CHANGED,
                Intent.ACTION_BATTERY_LOW,
                Intent.ACTION_BATTERY_OKAY,
                Intent.ACTION_POWER_CONNECTED,
                Intent.ACTION_POWER_DISCONNECTED
            ),
            AutostartCategory.LOCATION to listOf(
                "android.location.PROVIDERS_CHANGED",
                "android.location.MODE_CHANGED",
                "android.intent.action.PROVIDER_CHANGED"
            ),
            AutostartCategory.SCREEN to listOf(
                Intent.ACTION_SCREEN_ON,
                Intent.ACTION_SCREEN_OFF,
                Intent.ACTION_DREAMING_STARTED,
                Intent.ACTION_DREAMING_STOPPED
            ),
            AutostartCategory.CUSTOM to listOf(
                Intent.ACTION_PACKAGE_ADDED,
                Intent.ACTION_PACKAGE_REMOVED,
                Intent.ACTION_PACKAGE_REPLACED,
                Intent.ACTION_PACKAGE_CHANGED,
                Intent.ACTION_DATE_CHANGED,
                Intent.ACTION_TIME_TICK,
                Intent.ACTION_TIME_CHANGED,
                Intent.ACTION_TIMEZONE_CHANGED,
                "android.app.action.DEVICE_ADMIN_ENABLED",
                "android.app.action.DEVICE_ADMIN_DISABLE_REQUESTED",
                "android.bluetooth.device.action.ACL_CONNECTED",
                "android.bluetooth.device.action.ACL_DISCONNECTED",
                "android.bluetooth.adapter.action.STATE_CHANGED",
                Intent.ACTION_REBOOT,
                Intent.ACTION_SHUTDOWN
            )
        )
    }

    /**
     * Получить все приложения с автозапуском
     */
    fun getAutostartApps(): List<AutostartItem> {
        val autostarts = mutableListOf<AutostartItem>()
        val pm = context.packageManager

        for ((category, actions) in BOOT_ACTIONS) {
            for (action in actions) {
                try {
                    val intent = Intent(action)
                    val receivers = pm.queryBroadcastReceivers(intent, PackageManager.GET_META_DATA)

                    for (resolveInfo in receivers) {
                        try {
                            val activityInfo = resolveInfo.activityInfo
                            val packageName = activityInfo.packageName

                            // Пропускаем системные приёмники Android
                            if (packageName.startsWith("com.android.") &&
                                packageName != "com.android.providers.media") {
                                continue
                            }

                            val appInfo = try {
                                pm.getApplicationInfo(packageName, 0)
                            } catch (e: Exception) { continue }

                            val appName = try {
                                pm.getApplicationLabel(appInfo).toString()
                            } catch (e: Exception) { packageName }

                            val isSystem = Utils.isSystemApp(appInfo)
                            val icon = try {
                                pm.getApplicationIcon(appInfo)
                            } catch (e: Exception) { null }

                            // Вычисление уровня риска
                            val riskLevel = calculateAutostartRisk(
                                packageName, action, category, isSystem, resolveInfo
                            )

                            // Проверяем, не дублируется ли
                            val exists = autostarts.any {
                                it.packageName == packageName && it.action == action && it.category == category
                            }
                            if (!exists) {
                                autostarts.add(AutostartItem(
                                    packageName = packageName,
                                    appName = appName,
                                    icon = icon,
                                    receiverName = activityInfo.name,
                                    action = action,
                                    priority = resolveInfo.priority,
                                    isSystemApp = isSystem,
                                    isEnabled = activityInfo.enabled,
                                    riskLevel = riskLevel,
                                    category = category
                                ))
                            }
                        } catch (e: Exception) {
                            Log.w(TAG, "Error processing receiver", e)
                        }
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Error querying action: $action", e)
                }
            }
        }

        // Группировка по приложениям (одно приложение может иметь несколько автозапусков)
        return autostarts.sortedWith(compareBy({ it.riskLevel.ordinal }, { it.appName }))
    }

    /**
     * Получить количество автозапусков по категориям
     */
    fun getAutostartCounts(): Map<AutostartCategory, Int> {
        val counts = mutableMapOf<AutostartCategory, Int>()
        val apps = getAutostartApps()

        for (category in AutostartCategory.values()) {
            counts[category] = apps.count { it.category == category }
        }

        return counts
    }

    /**
     * Получить автозапуски для конкретного приложения
     */
    fun getAutostartsForApp(packageName: String): List<AutostartItem> {
        return getAutostartApps().filter { it.packageName == packageName }
    }

    /**
     * Вычисление уровня риска автозапуска
     */
    private fun calculateAutostartRisk(
        packageName: String,
        action: String,
        category: AutostartCategory,
        isSystem: Boolean,
        resolveInfo: ResolveInfo
    ): RiskLevel {
        var riskScore = 0

        // Системные приложения менее подозрительны
        if (isSystem) {
            riskScore -= 30
        }

        // Категория риска
        when (category) {
            AutostartCategory.BOOT -> riskScore += 10 // Нормально для многих приложений
            AutostartCategory.SMS -> riskScore += 40 // SMS приёмники — высокий риск
            AutostartCategory.CALL -> riskScore += 35 // Звонки — высокий риск
            AutostartCategory.NETWORK -> riskScore += 15
            AutostartCategory.MEDIA -> riskScore += 5
            AutostartCategory.USER_PRESENT -> riskScore += 15
            AutostartCategory.BATTERY -> riskScore += 5
            AutostartCategory.LOCATION -> riskScore += 20
            AutostartCategory.SCREEN -> riskScore += 15
            AutostartCategory.CUSTOM -> riskScore += 10
        }

        // Высокий приоритет приёмника
        if (resolveInfo.priority > 0) {
            riskScore += 15
        }

        // Проверка на подозрительные пакеты
        for (pattern in Utils.SUSPICIOUS_PACKAGE_PATTERNS) {
            if (pattern.matches(packageName)) {
                riskScore += 30
                break
            }
        }

        // Проверка на non-Play Store
        try {
            val installer = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
                context.packageManager.getInstallSourceInfo(packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getInstallerPackageName(packageName)
            }
            if (installer == null && !isSystem) {
                riskScore += 15
            }
        } catch (e: Exception) { }

        return when {
            riskScore <= 10 -> RiskLevel.SAFE
            riskScore <= 25 -> RiskLevel.LOW
            riskScore <= 40 -> RiskLevel.MEDIUM
            riskScore <= 60 -> RiskLevel.HIGH
            else -> RiskLevel.CRITICAL
        }
    }

    /**
     * Подсчитать общий score автозапусков
     */
    fun getAutostartSecurityScore(): Int {
        val apps = getAutostartApps()
        val nonSystemApps = apps.filter { !it.isSystemApp }
        val highRiskApps = nonSystemApps.count {
            it.riskLevel == RiskLevel.HIGH || it.riskLevel == RiskLevel.CRITICAL
        }
        val smsReceivers = nonSystemApps.count { it.category == AutostartCategory.SMS }
        val callReceivers = nonSystemApps.count { it.category == AutostartCategory.CALL }

        var score = 100
        score -= highRiskApps * 10
        score -= smsReceivers * 15
        score -= callReceivers * 10
        score -= (nonSystemApps.size * 2)

        return score.coerceAtLeast(0)
    }
}
