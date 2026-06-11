package com.securityguard.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.securityguard.engine.AutostartEngine
import com.securityguard.engine.ProcessEngine

/**
 * Приёмник загрузки устройства
 * Анализирует приложения, запускающиеся при старте системы
 */
class BootReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "BootReceiver"
    }

    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED,
            "android.intent.action.QUICKBOOT_POWERON" -> {
                Log.d(TAG, "Boot completed detected")
                analyzeBootApps(context)
            }
        }
    }

    private fun analyzeBootApps(context: Context) {
        Thread {
            try {
                val autostartEngine = AutostartEngine(context)
                val bootApps = autostartEngine.getAutostartApps()
                    .filter { it.category.name == "BOOT" && !it.isSystemApp }

                Log.d(TAG, "Found ${bootApps.size} non-system boot apps")

                // Сохраняем информацию о boot-приложениях
                val prefs = context.getSharedPreferences("security_guard", Context.MODE_PRIVATE)
                prefs.edit()
                    .putInt("boot_apps_count", bootApps.size)
                    .putLong("last_boot_time", System.currentTimeMillis())
                    .putString("boot_apps", bootApps.joinToString(",") { it.packageName })
                    .apply()

                // Оповещение о подозрительных boot-приложениях
                val suspicious = bootApps.filter {
                    it.riskLevel.name in listOf("HIGH", "CRITICAL")
                }
                if (suspicious.isNotEmpty()) {
                    showBootNotification(context, suspicious.size)
                }

            } catch (e: Exception) {
                Log.e(TAG, "Error analyzing boot apps", e)
            }
        }.start()
    }

    private fun showBootNotification(context: Context, count: Int) {
        // Уведомление о подозрительных автозапусках
        val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE)
            as android.app.NotificationManager

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            val channel = android.app.NotificationChannel(
                com.securityguard.SecurityGuardApp.CHANNEL_BOOT,
                "Автозапуск",
                android.app.NotificationManager.IMPORTANCE_LOW
            )
            notificationManager.createNotificationChannel(channel)
        }

        val notification = androidx.core.app.NotificationCompat.Builder(
            context,
            com.securityguard.SecurityGuardApp.CHANNEL_BOOT
        )
            .setContentTitle("Security Guard")
            .setContentText("При загрузке запустилось $count подозрительных приложений")
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setAutoCancel(true)
            .build()

        notificationManager.notify(2001, notification)
    }
}
