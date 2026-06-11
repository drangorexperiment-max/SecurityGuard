package com.securityguard

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build

class SecurityGuardApp : Application() {

    companion object {
        const val CHANNEL_SCAN = "scan_channel"
        const val CHANNEL_MONITOR = "monitor_channel"
        const val CHANNEL_ALERTS = "alerts_channel"
        const val CHANNEL_BOOT = "boot_channel"
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannels()
    }

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val scanChannel = NotificationChannel(
                CHANNEL_SCAN,
                "Сканирование",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Уведомления о процессе сканирования"
                setShowBadge(false)
            }

            val monitorChannel = NotificationChannel(
                CHANNEL_MONITOR,
                "Мониторинг",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Мониторинг процессов в реальном времени"
                setShowBadge(false)
            }

            val alertsChannel = NotificationChannel(
                CHANNEL_ALERTS,
                "Оповещения безопасности",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Критические оповещения об угрозах"
                enableVibration(true)
                enableLights(true)
            }

            val bootChannel = NotificationChannel(
                CHANNEL_BOOT,
                "Автозапуск",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Уведомления о приложениях автозапуска"
                setShowBadge(false)
            }

            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannels(
                listOf(scanChannel, monitorChannel, alertsChannel, bootChannel)
            )
        }
    }
}
