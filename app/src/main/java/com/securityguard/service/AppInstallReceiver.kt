package com.securityguard.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.securityguard.engine.ScanEngine
import com.securityguard.model.ThreatInfo

/**
 * Приёмник установки/удаления приложений
 * Автоматически сканирует новые или обновлённые приложения
 */
class AppInstallReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "AppInstallReceiver"
    }

    override fun onReceive(context: Context, intent: Intent) {
        val packageName = intent.data?.schemeSpecificPart ?: return

        when (intent.action) {
            Intent.ACTION_PACKAGE_ADDED -> {
                val replacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)
                if (!replacing) {
                    Log.d(TAG, "New app installed: $packageName")
                    scanNewApp(context, packageName)
                }
            }
            Intent.ACTION_PACKAGE_REPLACED -> {
                Log.d(TAG, "App updated: $packageName")
                scanNewApp(context, packageName)
            }
            Intent.ACTION_PACKAGE_REMOVED -> {
                Log.d(TAG, "App removed: $packageName")
                // Очищаем данные сканирования для удалённого приложения
            }
        }
    }

    private fun scanNewApp(context: Context, packageName: String) {
        Thread {
            try {
                val pm = context.packageManager
                val packageInfo = pm.getPackageInfo(
                    packageName,
                    android.content.pm.PackageManager.GET_PERMISSIONS or
                    android.content.pm.PackageManager.GET_SIGNATURES
                )

                val appInfo = packageInfo.applicationInfo
                val appName = pm.getApplicationLabel(appInfo).toString()

                // Быстрая проверка разрешений
                val permissions = packageInfo.requestedPermissions?.toList() ?: emptyList()
                val dangerousPerms = permissions.filter {
                    it in com.securityguard.util.Utils.DANGEROUS_PERMISSIONS
                }
                val criticalPerms = permissions.filter {
                    it in com.securityguard.util.Utils.CRITICAL_PERMISSIONS
                }

                // Вычисление быстрого риска
                var riskScore = dangerousPerms.size * 5 + criticalPerms.size * 15
                if (riskScore > 40) {
                    // Показываем уведомление о подозрительном приложении
                    showInstallAlert(context, appName, packageName, riskScore)
                }

                Log.d(TAG, "Quick scan of $packageName: risk=$riskScore, " +
                        "dangerous=${dangerousPerms.size}, critical=${criticalPerms.size}")

            } catch (e: Exception) {
                Log.e(TAG, "Error scanning new app: $packageName", e)
            }
        }.start()
    }

    private fun showInstallAlert(context: Context, appName: String, packageName: String, risk: Int) {
        val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE)
            as android.app.NotificationManager

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            val channel = android.app.NotificationChannel(
                com.securityguard.SecurityGuardApp.CHANNEL_ALERTS,
                "Оповещения безопасности",
                android.app.NotificationManager.IMPORTANCE_HIGH
            )
            notificationManager.createNotificationChannel(channel)
        }

        val notification = androidx.core.app.NotificationCompat.Builder(
            context,
            com.securityguard.SecurityGuardApp.CHANNEL_ALERTS
        )
            .setContentTitle("⚠️ Подозрительное приложение")
            .setContentText("$appName имеет высокий уровень риска ($risk/100)")
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setAutoCancel(true)
            .setPriority(androidx.core.app.NotificationCompat.PRIORITY_HIGH)
            .build()

        notificationManager.notify(packageName.hashCode(), notification)
    }
}
