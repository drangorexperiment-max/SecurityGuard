package com.securityguard.ui.privacy

import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.appbar.MaterialToolbar
import com.securityguard.R
import com.securityguard.util.Utils
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class PrivacyActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_privacy)

        val toolbar = findViewById<com.google.android.material.appbar.MaterialToolbar>(R.id.toolbar)
        toolbar.setNavigationOnClickListener { finish() }

        loadPrivacyData()
    }

    private fun loadPrivacyData() {
        lifecycleScope.launch {
            try {
                val pm = packageManager
                val packages = withContext(Dispatchers.IO) {
                    pm.getInstalledPackages(android.content.pm.PackageManager.GET_PERMISSIONS)
                }

                var cameraApps = 0; var micApps = 0; var locationApps = 0
                var callApps = 0; var smsApps = 0; var storageApps = 0; var trackerApps = 0
                val cameraAppList = mutableListOf<String>()
                val micAppList = mutableListOf<String>()
                val locationAppList = mutableListOf<String>()
                val callAppList = mutableListOf<String>()
                val smsAppList = mutableListOf<String>()

                for (pkg in packages) {
                    if (Utils.isSystemApp(pkg.applicationInfo)) continue
                    val perms = pkg.requestedPermissions?.toList() ?: continue
                    val name = pm.getApplicationLabel(pkg.applicationInfo).toString()

                    if (perms.any { it.contains("CAMERA") }) {
                        cameraApps++; cameraAppList.add(name)
                    }
                    if (perms.any { it.contains("RECORD_AUDIO") }) {
                        micApps++; micAppList.add(name)
                    }
                    if (perms.any { it.contains("LOCATION") }) {
                        locationApps++; locationAppList.add(name)
                    }
                    if (perms.any { it.contains("CALL") || it.contains("CONTACT") }) {
                        callApps++; callAppList.add(name)
                    }
                    if (perms.any { it.contains("SMS") }) {
                        smsApps++; smsAppList.add(name)
                    }
                    if (perms.any { it.contains("STORAGE") || it.contains("MANAGE_EXTERNAL") }) {
                        storageApps++
                    }
                    val tracking = perms.count { it in Utils.TRACKING_PERMISSIONS }
                    if (tracking >= 3) trackerApps++
                }

                // Обновляем UI
                findViewById<TextView>(R.id.tvCameraCount).text = cameraApps.toString()
                findViewById<TextView>(R.id.tvCameraApps).text =
                    if (cameraApps > 0) cameraAppList.take(3).joinToString(", ") + if (cameraApps > 3) "..." else "" else "Нет доступов"

                findViewById<TextView>(R.id.tvMicCount).text = micApps.toString()
                findViewById<TextView>(R.id.tvMicApps).text =
                    if (micApps > 0) micAppList.take(3).joinToString(", ") + if (micApps > 3) "..." else "" else "Нет доступов"

                findViewById<TextView>(R.id.tvLocationCount).text = locationApps.toString()
                findViewById<TextView>(R.id.tvLocationApps).text =
                    if (locationApps > 0) locationAppList.take(3).joinToString(", ") + if (locationApps > 3) "..." else "" else "Нет доступов"

                findViewById<TextView>(R.id.tvCallCount).text = callApps.toString()
                findViewById<TextView>(R.id.tvCallApps).text =
                    if (callApps > 0) callAppList.take(3).joinToString(", ") + if (callApps > 3) "..." else "" else "Нет доступов"

                findViewById<TextView>(R.id.tvSmsCount).text = smsApps.toString()
                findViewById<TextView>(R.id.tvSmsApps).text =
                    if (smsApps > 0) smsAppList.take(3).joinToString(", ") + if (smsApps > 3) "..." else "" else "Нет доступов"

                findViewById<TextView>(R.id.tvStorageCount).text = storageApps.toString()
                findViewById<TextView>(R.id.tvStorageApps).text =
                    "${storageApps} приложений имеют доступ к хранилищу"

                findViewById<TextView>(R.id.tvTrackerCount).text = trackerApps.toString()
                findViewById<TextView>(R.id.tvTrackerApps).text =
                    "${trackerApps} приложений с множественными разрешениями трекинга"

                // Общая оценка
                var score = 100
                score -= cameraApps * 2
                score -= micApps * 3
                score -= smsApps * 5
                score -= callApps * 3
                score -= trackerApps * 5
                score -= (locationApps * 1)
                score = score.coerceAtLeast(0)

                val tvScore = findViewById<TextView>(R.id.tvPrivacyScore)
                tvScore.text = score.toString()
                tvScore.setTextColor(Utils.getRiskColor(100 - score))

                val label = when {
                    score >= 80 -> "Отличная защита"
                    score >= 60 -> "Хорошая защита"
                    score >= 40 -> "Средняя защита"
                    score >= 20 -> "Слабая защита"
                    else -> "Критическая уязвимость"
                }
                findViewById<TextView>(R.id.tvPrivacyLabel).text = label

            } catch (e: Exception) { }
        }
    }
}
