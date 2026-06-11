package com.securityguard.service

import android.app.*
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import com.securityguard.R
import com.securityguard.SecurityGuardApp
import com.securityguard.engine.NetworkEngine
import com.securityguard.engine.ProcessEngine
import com.securityguard.ui.MainActivity
import kotlinx.coroutines.*

/**
 * Сервис мониторинга в реальном времени
 * Периодически проверяет процессы, сеть и состояние системы
 */
class MonitorService : Service() {

    companion object {
        private const val TAG = "MonitorService"
        const val NOTIFICATION_ID = 1002
        const val ACTION_START = "com.securityguard.START_MONITOR"
        const val ACTION_STOP = "com.securityguard.STOP_MONITOR"

        const val BROADCAST_MONITOR_UPDATE = "com.securityguard.MONITOR_UPDATE"
        const val BROADCAST_MONITOR_ALERT = "com.securityguard.MONITOR_ALERT"

        const val EXTRA_SUSPICIOUS_COUNT = "suspicious_count"
        const val EXTRA_PROCESS_COUNT = "process_count"
        const val EXTRA_CONNECTION_COUNT = "connection_count"

        private const val MONITOR_INTERVAL = 30_000L // 30 секунд
    }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var monitorJob: Job? = null
    private var isRunning = false

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "MonitorService created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startMonitoring()
            ACTION_STOP -> stopMonitoring()
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun startMonitoring() {
        if (isRunning) return
        isRunning = true
        showMonitorNotification("Мониторинг активен")

        monitorJob = scope.launch {
            while (isActive) {
                try {
                    performMonitoring()
                } catch (e: Exception) {
                    Log.e(TAG, "Monitor error", e)
                }
                delay(MONITOR_INTERVAL)
            }
        }
    }

    private suspend fun performMonitoring() {
        val processEngine = ProcessEngine(applicationContext)
        val networkEngine = NetworkEngine(applicationContext)

        // Проверка процессов
        val processes = processEngine.getRunningProcesses()
        val suspiciousProcesses = processes.filter { it.riskScore > 50 }

        // Проверка сети
        val networkStats = networkEngine.getNetworkStats()

        // Отправка обновлений
        val updateIntent = Intent(BROADCAST_MONITOR_UPDATE).apply {
            setPackage(packageName)
            putExtra(EXTRA_PROCESS_COUNT, processes.size)
            putExtra(EXTRA_SUSPICIOUS_COUNT, suspiciousProcesses.size)
            putExtra(EXTRA_CONNECTION_COUNT, networkStats.totalConnections)
        }
        sendBroadcast(updateIntent)

        // Оповещение о подозрительной активности
        if (suspiciousProcesses.isNotEmpty()) {
            val alertIntent = Intent(BROADCAST_MONITOR_ALERT).apply {
                setPackage(packageName)
                putExtra("type", "process")
                putExtra("message", "Обнаружено подозрительных процессов: ${suspiciousProcesses.size}")
            }
            sendBroadcast(alertIntent)
        }

        if (networkStats.suspiciousConnections > 0) {
            val alertIntent = Intent(BROADCAST_MONITOR_ALERT).apply {
                setPackage(packageName)
                putExtra("type", "network")
                putExtra("message", "Подозрительных подключений: ${networkStats.suspiciousConnections}")
            }
            sendBroadcast(alertIntent)
        }

        // Обновление уведомления
        val statusText = "Процессы: ${processes.size} | Соединения: ${networkStats.totalConnections}"
        if (suspiciousProcesses.isNotEmpty()) {
            showMonitorNotification("⚠️ $statusText | Подозрительных: ${suspiciousProcesses.size}")
        } else {
            showMonitorNotification("✓ $statusText")
        }
    }

    private fun showMonitorNotification(text: String) {
        createNotificationChannel()
        val notification = NotificationCompat.Builder(this, SecurityGuardApp.CHANNEL_MONITOR)
            .setContentTitle("Security Guard — Мониторинг")
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_monitor)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(
                PendingIntent.getActivity(
                    this, 0,
                    Intent(this, MainActivity::class.java),
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                )
            )
            .build()

        startForeground(NOTIFICATION_ID, notification)
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                SecurityGuardApp.CHANNEL_MONITOR,
                "Мониторинг",
                NotificationManager.IMPORTANCE_LOW
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun stopMonitoring() {
        monitorJob?.cancel()
        isRunning = false
        stopSelf()
    }

    override fun onDestroy() {
        super.onDestroy()
        monitorJob?.cancel()
        scope.cancel()
    }
}
