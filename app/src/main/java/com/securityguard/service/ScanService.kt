package com.securityguard.service

import android.app.*
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import com.securityguard.R
import com.securityguard.SecurityGuardApp
import com.securityguard.engine.ScanEngine
import com.securityguard.model.ScanResult
import com.securityguard.model.ScanType
import com.securityguard.ui.MainActivity
import kotlinx.coroutines.*

/**
 * Фоновый сервис сканирования
 * Выполняет полное или быстрое сканирование в фоновом режиме
 */
class ScanService : Service() {

    companion object {
        private const val TAG = "ScanService"
        const val NOTIFICATION_ID = 1001

        const val ACTION_START_SCAN = "com.securityguard.START_SCAN"
        const val ACTION_STOP_SCAN = "com.securityguard.STOP_SCAN"
        const val EXTRA_SCAN_TYPE = "scan_type"

        const val BROADCAST_SCAN_PROGRESS = "com.securityguard.SCAN_PROGRESS"
        const val BROADCAST_SCAN_COMPLETE = "com.securityguard.SCAN_COMPLETE"
        const val EXTRA_PROGRESS = "progress"
        const val EXTRA_STATUS = "status"
        const val EXTRA_RESULT = "scan_result"
    }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var scanJob: Job? = null
    private var isScanning = false

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "ScanService created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START_SCAN -> {
                val scanType = intent.getStringExtra(EXTRA_SCAN_TYPE) ?: "QUICK"
                startScan(scanType)
            }
            ACTION_STOP_SCAN -> {
                stopScan()
            }
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun startScan(scanType: String) {
        if (isScanning) {
            Log.w(TAG, "Scan already in progress")
            return
        }

        isScanning = true
        showNotification(0, "Инициализация сканирования...")

        scanJob = scope.launch {
            try {
                val engine = ScanEngine(applicationContext)
                val result = when (scanType) {
                    "FULL" -> engine.fullScan { progress, status ->
                        updateNotification(progress, status)
                        sendProgressBroadcast(progress, status)
                    }
                    else -> engine.quickScan { progress, status ->
                        updateNotification(progress, status)
                        sendProgressBroadcast(progress, status)
                    }
                }

                // Сохраняем результат
                saveScanResult(result)

                // Отправляем результат
                sendCompleteBroadcast(result)

                // Обновляем уведомление
                val threatCount = result.threatsFound.size
                showCompleteNotification(threatCount)

            } catch (e: CancellationException) {
                Log.d(TAG, "Scan cancelled")
                showNotification(0, "Сканирование отменено")
            } catch (e: Exception) {
                Log.e(TAG, "Scan error", e)
                showNotification(0, "Ошибка сканирования: ${e.message}")
            } finally {
                isScanning = false
                stopSelf()
            }
        }
    }

    private fun stopScan() {
        scanJob?.cancel()
        isScanning = false
        updateNotification(0, "Сканирование остановлено")
        stopSelf()
    }

    private fun showNotification(progress: Int, status: String) {
        createNotificationChannel()
        val notification = NotificationCompat.Builder(this, SecurityGuardApp.CHANNEL_SCAN)
            .setContentTitle("Security Guard — Сканирование")
            .setContentText(status)
            .setSmallIcon(R.drawable.ic_scan)
            .setProgress(100, progress, progress == 0)
            .setOngoing(true)
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

    private fun updateNotification(progress: Int, status: String) {
        createNotificationChannel()
        val notification = NotificationCompat.Builder(this, SecurityGuardApp.CHANNEL_SCAN)
            .setContentTitle("Security Guard — Сканирование")
            .setContentText(status)
            .setSmallIcon(R.drawable.ic_scan)
            .setProgress(100, progress, false)
            .setOngoing(true)
            .setContentIntent(
                PendingIntent.getActivity(
                    this, 0,
                    Intent(this, MainActivity::class.java),
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                )
            )
            .build()

        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID, notification)
    }

    private fun showCompleteNotification(threatCount: Int) {
        val title = if (threatCount == 0) "Угроз не обнаружено!" else "Обнаружено угроз: $threatCount"
        val notification = NotificationCompat.Builder(this, SecurityGuardApp.CHANNEL_SCAN)
            .setContentTitle(title)
            .setContentText("Сканирование завершено")
            .setSmallIcon(R.drawable.ic_scan)
            .setAutoCancel(true)
            .setContentIntent(
                PendingIntent.getActivity(
                    this, 0,
                    Intent(this, MainActivity::class.java),
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                )
            )
            .build()

        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID + 1, notification)
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                SecurityGuardApp.CHANNEL_SCAN,
                "Сканирование",
                NotificationManager.IMPORTANCE_LOW
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun sendProgressBroadcast(progress: Int, status: String) {
        val intent = Intent(BROADCAST_SCAN_PROGRESS)
        intent.setPackage(packageName)
        intent.putExtra(EXTRA_PROGRESS, progress)
        intent.putExtra(EXTRA_STATUS, status)
        sendBroadcast(intent)
    }

    private fun sendCompleteBroadcast(result: ScanResult) {
        val intent = Intent(BROADCAST_SCAN_COMPLETE)
        intent.setPackage(packageName)
        intent.putExtra(EXTRA_RESULT, result)
        sendBroadcast(intent)
    }

    private fun saveScanResult(result: ScanResult) {
        val prefs = getSharedPreferences("security_guard", MODE_PRIVATE)
        prefs.edit()
            .putLong("last_scan_time", result.endTime)
            .putInt("last_scan_threats", result.threatsFound.size)
            .putInt("last_scan_apps", result.appsScanned)
            .putLong("last_scan_files", result.filesScanned)
            .apply()
    }

    override fun onDestroy() {
        super.onDestroy()
        scanJob?.cancel()
        scope.cancel()
    }
}
