package com.securityguard.ui.scanner

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.appbar.MaterialToolbar
import com.securityguard.R
import com.securityguard.engine.ScanEngine
import com.securityguard.model.ScanType
import com.securityguard.model.ThreatInfo
import com.securityguard.util.Utils
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ScanActivity : AppCompatActivity() {

    private lateinit var progressBar: ProgressBar
    private lateinit var tvProgress: TextView
    private lateinit var tvStatus: TextView
    private lateinit var layoutResults: View
    private lateinit var tvResultTitle: TextView
    private lateinit var tvResultDetails: TextView
    private lateinit var recyclerThreats: RecyclerView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_scan)

        val toolbar = findViewById<MaterialToolbar>(R.id.toolbar)
        toolbar.setNavigationOnClickListener { finish() }

        progressBar = findViewById(R.id.progressBar)
        tvProgress = findViewById(R.id.tvScanProgress)
        tvStatus = findViewById(R.id.tvScanStatus)
        layoutResults = findViewById(R.id.layoutResults)
        tvResultTitle = findViewById(R.id.tvResultTitle)
        tvResultDetails = findViewById(R.id.tvResultDetails)
        recyclerThreats = findViewById(R.id.recyclerThreats)

        val scanType = intent.getStringExtra("scan_type") ?: "QUICK"
        startScan(scanType)
    }

    private fun startScan(type: String) {
        lifecycleScope.launch {
            try {
                val engine = ScanEngine(this@ScanActivity)
                val result = when (type) {
                    "FULL" -> engine.fullScan { progress, status ->
                        runOnUiThread {
                            progressBar.progress = progress
                            tvProgress.text = "$progress%"
                            tvStatus.text = status
                        }
                    }
                    else -> engine.quickScan { progress, status ->
                        runOnUiThread {
                            progressBar.progress = progress
                            tvProgress.text = "$progress%"
                            tvStatus.text = status
                        }
                    }
                }

                showResults(result)
            } catch (e: Exception) {
                tvStatus.text = "Ошибка: ${e.message}"
            }
        }
    }

    private fun showResults(result: com.securityguard.model.ScanResult) {
        layoutResults.visibility = View.VISIBLE

        val threatCount = result.threatsFound.size
        val scanDuration = result.endTime - result.startTime

        tvResultTitle.text = if (threatCount == 0) "✅ Угроз не обнаружено!" else "⚠️ Обнаружено угроз: $threatCount"
        tvResultTitle.setTextColor(
            if (threatCount == 0) getColor(R.color.safe) else getColor(R.color.danger)
        )

        tvResultDetails.text = buildString {
            append("Тип сканирования: ${result.scanType.name}\n")
            append("Длительность: ${Utils.formatDuration(scanDuration)}\n")
            append("Файлов проверено: ${result.filesScanned}\n")
            append("Приложений проверено: ${result.appsScanned}\n")
            append("Угроз обнаружено: $threatCount\n")
        }

        if (result.threatsFound.isNotEmpty()) {
            recyclerThreats.layoutManager = LinearLayoutManager(this)
            recyclerThreats.adapter = ThreatAdapter(result.threatsFound)
        }
    }

    class ThreatAdapter(private val threats: List<ThreatInfo>) :
        RecyclerView.Adapter<ThreatAdapter.VH>() {

        class VH(view: View) : RecyclerView.ViewHolder(view) {
            val tvName: TextView = view.findViewById(R.id.tvThreatName)
            val tvType: TextView = view.findViewById(R.id.tvThreatType)
            val tvDescription: TextView = view.findViewById(R.id.tvThreatDesc)
            val tvSeverity: TextView = view.findViewById(R.id.tvThreatSeverity)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
            val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_threat, parent, false)
            return VH(view)
        }

        override fun onBindViewHolder(holder: VH, position: Int) {
            val threat = threats[position]
            holder.tvName.text = threat.name
            holder.tvType.text = threat.type.name
            holder.tvDescription.text = threat.description

            val (text, color) = when (threat.severity) {
                com.securityguard.model.ThreatSeverity.CRITICAL -> "⛔ CRITICAL" to 0xFFF44336.toInt()
                com.securityguard.model.ThreatSeverity.HIGH -> "🔴 HIGH" to 0xFFFF5722.toInt()
                com.securityguard.model.ThreatSeverity.MEDIUM -> "🟡 MEDIUM" to 0xFFFFC107.toInt()
                com.securityguard.model.ThreatSeverity.LOW -> "🟢 LOW" to 0xFF8BC34A.toInt()
                com.securityguard.model.ThreatSeverity.INFO -> "ℹ️ INFO" to 0xFF2196F3.toInt()
            }
            holder.tvSeverity.text = text
            holder.tvSeverity.setTextColor(color)
        }

        override fun getItemCount() = threats.size
    }
}
