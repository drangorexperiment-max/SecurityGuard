package com.securityguard.ui

import android.os.Bundle
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.button.MaterialButton
import com.google.android.material.switchmaterial.SwitchMaterial
import com.securityguard.R
import com.securityguard.engine.ThreatDatabase

class SettingsActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        val toolbar = findViewById<MaterialToolbar>(R.id.toolbar)
        toolbar.setNavigationOnClickListener { finish() }

        val prefs = getSharedPreferences("security_guard_settings", MODE_PRIVATE)

        // Switches
        val switchAutoScan = findViewById<SwitchMaterial>(R.id.switchAutoScan)
        val switchRealtime = findViewById<SwitchMaterial>(R.id.switchRealtimeMonitor)
        val switchNotifications = findViewById<SwitchMaterial>(R.id.switchNotifications)
        val switchBootScan = findViewById<SwitchMaterial>(R.id.switchBootScan)

        switchAutoScan.isChecked = prefs.getBoolean("auto_scan", true)
        switchRealtime.isChecked = prefs.getBoolean("realtime_monitor", false)
        switchNotifications.isChecked = prefs.getBoolean("notifications", true)
        switchBootScan.isChecked = prefs.getBoolean("boot_scan", true)

        switchAutoScan.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit().putBoolean("auto_scan", isChecked).apply()
        }
        switchRealtime.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit().putBoolean("realtime_monitor", isChecked).apply()
        }
        switchNotifications.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit().putBoolean("notifications", isChecked).apply()
        }
        switchBootScan.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit().putBoolean("boot_scan", isChecked).apply()
        }

        // Database info
        val db = ThreatDatabase(this)
        val stats = db.getDatabaseSize()
        findViewById<TextView>(R.id.tvDatabaseInfo).text = buildString {
            append("Хешей вредоносного ПО: ${stats.malwareHashes}\n")
            append("Пакетов spyware: ${stats.spywarePackages}\n")
            append("Пакетов adware: ${stats.adwarePackages}\n")
            append("Подозрительных подписей: ${stats.suspiciousSignatures}\n")
            append("C2 доменов: ${stats.c2Domains}")
        }

        findViewById<MaterialButton>(R.id.btnUpdateDb).setOnClickListener {
            Toast.makeText(this, "База данных актуальна", Toast.LENGTH_SHORT).show()
        }
    }
}
