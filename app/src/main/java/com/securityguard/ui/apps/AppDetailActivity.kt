package com.securityguard.ui.apps

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.button.MaterialButton
import com.securityguard.R
import com.securityguard.util.Utils

class AppDetailActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_app_detail)

        val toolbar = findViewById<MaterialToolbar>(R.id.toolbar)
        toolbar.setNavigationOnClickListener { finish() }

        val packageName = intent.getStringExtra("package_name") ?: run {
            finish()
            return
        }

        loadAppDetails(packageName)

        findViewById<MaterialButton>(R.id.btnUninstall).setOnClickListener {
            val intent = Intent(Intent.ACTION_DELETE, Uri.parse("package:$packageName"))
            startActivity(intent)
        }

        findViewById<MaterialButton>(R.id.btnAppSettings).setOnClickListener {
            val intent = Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                Uri.parse("package:$packageName"))
            startActivity(intent)
        }
    }

    private fun loadAppDetails(packageName: String) {
        try {
            val pm = packageManager
            val pkgInfo = pm.getPackageInfo(
                packageName,
                android.content.pm.PackageManager.GET_PERMISSIONS or
                android.content.pm.PackageManager.GET_SIGNATURES or
                android.content.pm.PackageManager.GET_META_DATA
            )

            val appInfo = pkgInfo.applicationInfo
            val appName = pm.getApplicationLabel(appInfo).toString()
            val isSystem = Utils.isSystemApp(appInfo)

            // Header
            val ivIcon = findViewById<ImageView>(R.id.ivAppIcon)
            try { ivIcon.setImageDrawable(pm.getApplicationIcon(appInfo)) }
            catch (e: Exception) { }

            findViewById<TextView>(R.id.tvAppName).text = appName
            findViewById<TextView>(R.id.tvPackageName).text = packageName
            findViewById<TextView>(R.id.tvVersion).text =
                "v${pkgInfo.versionName} (${if (android.os.Build.VERSION.SDK_INT >= 28) pkgInfo.longVersionCode else pkgInfo.versionCode})"

            // Details
            val details = buildString {
                append("Установлено: ${Utils.formatTime(pkgInfo.firstInstallTime)}\n")
                append("Обновлено: ${Utils.formatTime(pkgInfo.lastUpdateTime)}\n")
                append("APK: ${appInfo.sourceDir}\n")
                append("Размер: ${Utils.formatSize(java.io.File(appInfo.sourceDir).length())}\n")
                append("Target SDK: ${appInfo.targetSdkVersion}\n")
                append("Min SDK: ${appInfo.minSdkVersion}\n")
                append("UID: ${appInfo.uid}\n")
                append("Системное: ${if (isSystem) "Да" else "Нет"}\n")
                append("Отлаживаемое: ${if ((appInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0) "⚠️ Да" else "Нет"}\n")
                append("Backup: ${if ((appInfo.flags and android.content.pm.ApplicationInfo.FLAG_ALLOW_BACKUP) != 0) "Да" else "Нет"}\n")

                val installer = if (android.os.Build.VERSION.SDK_INT >= 30) {
                    pm.getInstallSourceInfo(packageName).installingPackageName
                } else {
                    @Suppress("DEPRECATION")
                    pm.getInstallerPackageName(packageName)
                }
                append("Источник: ${installer ?: "Неизвестный (sideload)"}\n")

                val sigs = Utils.getApkSignature(this@AppDetailActivity, packageName)
                if (sigs.isNotEmpty()) {
                    append("\nПодпись SHA-256:\n${sigs.first().take(40)}...\n")
                }
            }
            findViewById<TextView>(R.id.tvDetails).text = details

            // Permissions
            val perms = pkgInfo.requestedPermissions?.toList() ?: emptyList()
            val dangerousPerms = perms.filter { it in Utils.DANGEROUS_PERMISSIONS }
            val criticalPerms = perms.filter { it in Utils.CRITICAL_PERMISSIONS }
            val trackingPerms = perms.filter { it in Utils.TRACKING_PERMISSIONS }

            val permText = buildString {
                append("Всего разрешений: ${perms.size}\n")
                append("Опасных: ${dangerousPerms.size}\n")
                append("Критических: ${criticalPerms.size}\n")
                append("Трекинга: ${trackingPerms.size}\n\n")

                if (criticalPerms.isNotEmpty()) {
                    append("⛔ КРИТИЧЕСКИЕ:\n")
                    criticalPerms.forEach { perm ->
                        append("• ${perm.substringAfterLast(".")}\n")
                    }
                    append("\n")
                }

                if (dangerousPerms.isNotEmpty()) {
                    append("⚠️ Опасные:\n")
                    dangerousPerms.forEach { perm ->
                        append("• ${perm.substringAfterLast(".")}\n")
                    }
                    append("\n")
                }

                if (trackingPerms.isNotEmpty()) {
                    append("📍 Трекинг:\n")
                    trackingPerms.forEach { perm ->
                        append("• ${perm.substringAfterLast(".")}\n")
                    }
                }
            }
            findViewById<TextView>(R.id.tvPermissions).text = permText

            // Risk Analysis
            val riskScore = Utils.calculatePermissionRisk(dangerousPerms, criticalPerms)
            var totalRisk = riskScore

            val riskReasons = mutableListOf<String>()
            if (criticalPerms.isNotEmpty()) {
                riskReasons.add("Критические разрешения: ${criticalPerms.size}")
            }
            if (dangerousPerms.size > 5) {
                riskReasons.add("Слишком много опасных разрешений")
                totalRisk += 10
            }
            if ((appInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
                riskReasons.add("Приложение отлаживаемое")
                totalRisk += 30
            }
            if (appInfo.targetSdkVersion < 28) {
                riskReasons.add("Низкий targetSdkVersion — обход новых ограничений")
                totalRisk += 10
            }

            val hasSms = perms.any { it.contains("SMS") }
            val hasInternet = perms.contains("android.permission.INTERNET")
            val hasCamera = perms.contains("android.permission.CAMERA")
            val hasMic = perms.contains("android.permission.RECORD_AUDIO")
            if (hasSms && hasInternet) {
                riskReasons.add("SMS + Интернет = риск premium-SMS/утечки")
                totalRisk += 25
            }
            if (hasCamera && hasMic && hasInternet) {
                riskReasons.add("Камера + Микрофон + Интернет = шпионский потенциал")
                totalRisk += 20
            }

            totalRisk = totalRisk.coerceAtMost(100)

            val riskText = buildString {
                append("Общий риск: $totalRisk/100\n\n")
                if (riskReasons.isEmpty()) {
                    append("✅ Признаков риска не обнаружено\n")
                } else {
                    riskReasons.forEach { reason ->
                        append("⚠️ $reason\n")
                    }
                }
            }
            findViewById<TextView>(R.id.tvRiskAnalysis).text = riskText

            // Risk score display
            val tvRiskScore = findViewById<TextView>(R.id.tvRiskScore)
            tvRiskScore.text = totalRisk.toString()
            tvRiskScore.setTextColor(Utils.getRiskColor(totalRisk))

        } catch (e: Exception) {
            Toast.makeText(this, "Ошибка: ${e.message}", Toast.LENGTH_SHORT).show()
            finish()
        }
    }
}
