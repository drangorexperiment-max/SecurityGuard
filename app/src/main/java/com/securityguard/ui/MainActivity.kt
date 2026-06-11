package com.securityguard.ui

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.securityguard.R
import com.securityguard.engine.*
import com.securityguard.model.SecurityScore
import com.securityguard.service.MonitorService
import com.securityguard.service.ScanService
import com.securityguard.ui.apps.AppAnalyzerActivity
import com.securityguard.ui.autostart.AutostartActivity
import com.securityguard.ui.network.NetworkActivity
import com.securityguard.ui.permissions.PermissionActivity
import com.securityguard.ui.privacy.PrivacyActivity
import com.securityguard.ui.processes.ProcessActivity
import com.securityguard.ui.scanner.ScanActivity
import com.securityguard.util.Utils
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {

    // Views
    private lateinit var tvScoreValue: TextView
    private lateinit var tvScoreLabel: TextView
    private lateinit var tvMalwareScore: TextView
    private lateinit var tvPermScore: TextView
    private lateinit var tvNetScore: TextView
    private lateinit var tvPrivacyScore: TextView
    private lateinit var tvAutostartScore: TextView
    private lateinit var tvSystemScore: TextView
    private lateinit var tvAppsCount: TextView
    private lateinit var tvProcessesCount: TextView
    private lateinit var tvAutostartCount: TextView
    private lateinit var tvNetworkCount: TextView
    private lateinit var tvPermCount: TextView
    private lateinit var tvPrivacyCount: TextView
    private lateinit var tvLastScanTime: TextView
    private lateinit var tvLastScanThreats: TextView
    private lateinit var layoutScanProgress: LinearLayout
    private lateinit var tvScanStatus: TextView
    private lateinit var progressScan: android.widget.ProgressBar
    private lateinit var layoutAlerts: LinearLayout

    private var isMonitorActive = false
    private var isScanning = false

    private val scanReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                ScanService.BROADCAST_SCAN_PROGRESS -> {
                    val progress = intent.getIntExtra(ScanService.EXTRA_PROGRESS, 0)
                    val status = intent.getStringExtra(ScanService.EXTRA_STATUS) ?: ""
                    updateScanProgress(progress, status)
                }
                ScanService.BROADCAST_SCAN_COMPLETE -> {
                    onScanComplete()
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        initViews()
        setupClickListeners()
        registerReceivers()
        loadDashboard()
    }

    private fun initViews() {
        tvScoreValue = findViewById(R.id.tvScoreValue)
        tvScoreLabel = findViewById(R.id.tvScoreLabel)
        tvMalwareScore = findViewById(R.id.tvMalwareScore)
        tvPermScore = findViewById(R.id.tvPermScore)
        tvNetScore = findViewById(R.id.tvNetScore)
        tvPrivacyScore = findViewById(R.id.tvPrivacyScore)
        tvAutostartScore = findViewById(R.id.tvAutostartScore)
        tvSystemScore = findViewById(R.id.tvSystemScore)
        tvAppsCount = findViewById(R.id.tvAppsCount)
        tvProcessesCount = findViewById(R.id.tvProcessesCount)
        tvAutostartCount = findViewById(R.id.tvAutostartCount)
        tvNetworkCount = findViewById(R.id.tvNetworkCount)
        tvPermCount = findViewById(R.id.tvPermCount)
        tvPrivacyCount = findViewById(R.id.tvPrivacyCount)
        tvLastScanTime = findViewById(R.id.tvLastScanTime)
        tvLastScanThreats = findViewById(R.id.tvLastScanThreats)
        layoutScanProgress = findViewById(R.id.layoutScanProgress)
        tvScanStatus = findViewById(R.id.tvScanStatus)
        progressScan = findViewById(R.id.progressScan)
        layoutAlerts = findViewById(R.id.layoutAlerts)
    }

    private fun setupClickListeners() {
        findViewById<MaterialButton>(R.id.btnQuickScan).setOnClickListener {
            startScan("QUICK")
        }

        findViewById<MaterialButton>(R.id.btnFullScan).setOnClickListener {
            startScan("FULL")
        }

        findViewById<MaterialButton>(R.id.btnCancelScan).setOnClickListener {
            stopScan()
        }

        findViewById<MaterialCardView>(R.id.cardApps).setOnClickListener {
            startActivity(Intent(this, AppAnalyzerActivity::class.java))
        }

        findViewById<MaterialCardView>(R.id.cardProcesses).setOnClickListener {
            startActivity(Intent(this, ProcessActivity::class.java))
        }

        findViewById<MaterialCardView>(R.id.cardAutostart).setOnClickListener {
            startActivity(Intent(this, AutostartActivity::class.java))
        }

        findViewById<MaterialCardView>(R.id.cardNetwork).setOnClickListener {
            startActivity(Intent(this, NetworkActivity::class.java))
        }

        findViewById<MaterialCardView>(R.id.cardPermissions).setOnClickListener {
            startActivity(Intent(this, PermissionActivity::class.java))
        }

        findViewById<MaterialCardView>(R.id.cardPrivacy).setOnClickListener {
            startActivity(Intent(this, PrivacyActivity::class.java))
        }

        findViewById<com.google.android.material.appbar.MaterialToolbar>(R.id.toolbar)
            .setOnMenuItemClickListener { item ->
                when (item.itemId) {
                    R.id.action_refresh -> {
                        loadDashboard()
                        true
                    }
                    R.id.action_monitor -> {
                        toggleMonitor()
                        true
                    }
                    R.id.action_settings -> {
                        startActivity(Intent(this, SettingsActivity::class.java))
                        true
                    }
                    else -> false
                }
            }
    }

    private fun registerReceivers() {
        val filter = IntentFilter().apply {
            addAction(ScanService.BROADCAST_SCAN_PROGRESS)
            addAction(ScanService.BROADCAST_SCAN_COMPLETE)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(scanReceiver, filter, RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(scanReceiver, filter)
        }
    }

    private fun loadDashboard() {
        lifecycleScope.launch {
            try {
                // Вычисление security score
                val scoreEngine = SecurityScoreEngine(this@MainActivity)
                val score = withContext(Dispatchers.IO) {
                    scoreEngine.calculateSecurityScore()
                }
                updateScore(score)

                // Загрузка статистики
                loadStats()

                // Проверка системных проблем
                checkSystemIssues()

            } catch (e: Exception) {
                Toast.makeText(this@MainActivity, "Ошибка загрузки: ${e.message}",
                    Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun updateScore(score: SecurityScore) {
        tvScoreValue.text = score.overallScore.toString()

        val (label, color) = when {
            score.overallScore >= 80 -> "Отлично" to getColor(R.color.safe)
            score.overallScore >= 60 -> "Хорошо" to getColor(R.color.info)
            score.overallScore >= 40 -> "Средне" to getColor(R.color.warning)
            score.overallScore >= 20 -> "Плохо" to getColor(R.color.orange_500)
            else -> "Опасно" to getColor(R.color.critical)
        }

        tvScoreValue.setTextColor(color)
        tvScoreLabel.text = label
        tvScoreLabel.setTextColor(color)

        tvMalwareScore.text = score.malwareScore.toString()
        tvPermScore.text = score.permissionScore.toString()
        tvNetScore.text = score.networkScore.toString()
        tvPrivacyScore.text = score.privacyScore.toString()
        tvAutostartScore.text = score.autostartScore.toString()
        tvSystemScore.text = score.systemScore.toString()

        // Цвета для sub-scores
        tvMalwareScore.setTextColor(Utils.getRiskColor(100 - score.malwareScore))
        tvPermScore.setTextColor(Utils.getRiskColor(100 - score.permissionScore))
        tvNetScore.setTextColor(Utils.getRiskColor(100 - score.networkScore))
        tvPrivacyScore.setTextColor(Utils.getRiskColor(100 - score.privacyScore))
        tvAutostartScore.setTextColor(Utils.getRiskColor(100 - score.autostartScore))
        tvSystemScore.setTextColor(Utils.getRiskColor(100 - score.systemScore))
    }

    private suspend fun loadStats() {
        withContext(Dispatchers.IO) {
            // Подсчёт приложений
            val pm = packageManager
            val packages = pm.getInstalledPackages(0)
            val userApps = packages.count {
                (it.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) == 0
            }

            // Процессы
            val processEngine = ProcessEngine(this@MainActivity)
            val processes = processEngine.getRunningProcesses()

            // Автозапуски
            val autostartEngine = AutostartEngine(this@MainActivity)
            val autostarts = autostartEngine.getAutostartApps()
                .filter { !it.isSystemApp }

            // Сеть
            val networkEngine = NetworkEngine(this@MainActivity)
            val netStats = networkEngine.getNetworkStats()

            // Опасные разрешения
            val permPackages = pm.getInstalledPackages(android.content.pm.PackageManager.GET_PERMISSIONS)
            var criticalPerms = 0
            for (pkg in permPackages) {
                if (Utils.isSystemApp(pkg.applicationInfo)) continue
                val perms = pkg.requestedPermissions?.toList() ?: emptyList()
                criticalPerms += perms.count { it in Utils.CRITICAL_PERMISSIONS }
            }

            // Приватность
            var trackingApps = 0
            for (pkg in permPackages) {
                if (Utils.isSystemApp(pkg.applicationInfo)) continue
                val perms = pkg.requestedPermissions?.toList() ?: emptyList()
                val tracking = perms.count { it in Utils.TRACKING_PERMISSIONS }
                if (tracking >= 3) trackingApps++
            }

            withContext(Dispatchers.Main) {
                tvAppsCount.text = "$userApps приложений"
                tvProcessesCount.text = "${processes.size} процессов"
                tvAutostartCount.text = "${autostarts.size} приложений"
                tvNetworkCount.text = "${netStats.totalConnections} подключений"
                tvPermCount.text = "$criticalPerms крит. разрешений"
                tvPrivacyCount.text = "$trackingApps трекеров"
            }
        }

        // Last scan
        val prefs = getSharedPreferences("security_guard", MODE_PRIVATE)
        val lastScanTime = prefs.getLong("last_scan_time", 0L)
        val lastScanThreats = prefs.getInt("last_scan_threats", 0)

        withContext(Dispatchers.Main) {
            if (lastScanTime > 0) {
                tvLastScanTime.text = Utils.formatTime(lastScanTime)
                tvLastScanThreats.text = if (lastScanThreats > 0) {
                    "⚠️ $lastScanThreats угроз"
                } else {
                    "✓ Угроз нет"
                }
                tvLastScanThreats.setTextColor(
                    if (lastScanThreats > 0) getColor(R.color.danger)
                    else getColor(R.color.safe)
                )
            }
        }
    }

    private fun checkSystemIssues() {
        val alerts = mutableListOf<Pair<String, Int>>()

        // Root check
        val rootPaths = arrayOf("/system/bin/su", "/system/xbin/su", "/sbin/su")
        if (rootPaths.any { java.io.File(it).exists() }) {
            alerts.add("⚠️ Обнаружен Root-доступ" to getColor(R.color.danger))
        }

        // ADB
        if (android.provider.Settings.Global.getInt(
                contentResolver, android.provider.Settings.Global.ADB_ENABLED, 0
            ) == 1
        ) {
            alerts.add("⚠️ ADB-отладка включена" to getColor(R.color.warning))
        }

        // Screen lock
        val km = getSystemService(KEYGUARD_SERVICE) as android.app.KeyguardManager
        if (!km.isDeviceSecure) {
            alerts.add("⚠️ Нет блокировки экрана" to getColor(R.color.warning))
        }

        if (alerts.isNotEmpty()) {
            layoutAlerts.removeAllViews()
            for ((text, color) in alerts) {
                val tv = TextView(this).apply {
                    this.text = text
                    setTextColor(color)
                    textSize = 14f
                    setPadding(24, 12, 24, 12)
                }
                val card = com.google.android.material.card.MaterialCardView(this).apply {
                    layoutParams = LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT
                    ).apply { bottomMargin = 8 }
                    cardElevation = 4f
                    radius = 12f
                    addView(tv)
                }
                layoutAlerts.addView(card)
            }
            layoutAlerts.visibility = View.VISIBLE
        } else {
            layoutAlerts.visibility = View.GONE
        }
    }

    private fun startScan(type: String) {
        if (isScanning) {
            Toast.makeText(this, "Сканирование уже выполняется", Toast.LENGTH_SHORT).show()
            return
        }

        isScanning = true
        layoutScanProgress.visibility = View.VISIBLE

        val intent = Intent(this, ScanService::class.java).apply {
            action = ScanService.ACTION_START_SCAN
            putExtra(ScanService.EXTRA_SCAN_TYPE, type)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    private fun stopScan() {
        val intent = Intent(this, ScanService::class.java).apply {
            action = ScanService.ACTION_STOP_SCAN
        }
        startService(intent)
        isScanning = false
        layoutScanProgress.visibility = View.GONE
    }

    private fun updateScanProgress(progress: Int, status: String) {
        progressScan.progress = progress
        tvScanStatus.text = status
    }

    private fun onScanComplete() {
        isScanning = false
        layoutScanProgress.visibility = View.GONE
        loadDashboard()
        Toast.makeText(this, getString(R.string.scan_complete), Toast.LENGTH_SHORT).show()
    }

    private fun toggleMonitor() {
        if (isMonitorActive) {
            stopService(Intent(this, MonitorService::class.java))
            isMonitorActive = false
            Toast.makeText(this, "Мониторинг остановлен", Toast.LENGTH_SHORT).show()
        } else {
            val intent = Intent(this, MonitorService::class.java).apply {
                action = MonitorService.ACTION_START
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(intent)
            } else {
                startService(intent)
            }
            isMonitorActive = true
            Toast.makeText(this, "Мониторинг запущен", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        try {
            unregisterReceiver(scanReceiver)
        } catch (e: Exception) { }
    }

    override fun onResume() {
        super.onResume()
        // Обновляем данные при возврате на экран
    }
}
