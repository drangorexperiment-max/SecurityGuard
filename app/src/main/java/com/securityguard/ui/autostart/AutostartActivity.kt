package com.securityguard.ui.autostart

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout
import com.google.android.material.appbar.MaterialToolbar
import com.securityguard.R
import com.securityguard.engine.AutostartEngine
import com.securityguard.model.AutostartCategory
import com.securityguard.model.AutostartItem
import com.securityguard.model.RiskLevel
import com.securityguard.util.Utils
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class AutostartActivity : AppCompatActivity() {

    private lateinit var recycler: RecyclerView
    private lateinit var swipeRefresh: SwipeRefreshLayout
    private lateinit var tvBootCount: TextView
    private lateinit var tvSmsCount: TextView
    private lateinit var tvNetworkCount: TextView
    private lateinit var tvHighRisk: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_autostart)

        val toolbar = findViewById<MaterialToolbar>(R.id.toolbar)
        toolbar.setNavigationOnClickListener { finish() }

        recycler = findViewById(R.id.recyclerAutostarts)
        recycler.layoutManager = LinearLayoutManager(this)

        swipeRefresh = findViewById(R.id.swipeRefresh)
        swipeRefresh.setColorSchemeColors(getColor(R.color.accent))
        swipeRefresh.setOnRefreshListener { loadAutostarts() }

        tvBootCount = findViewById(R.id.tvBootCount)
        tvSmsCount = findViewById(R.id.tvSmsCount)
        tvNetworkCount = findViewById(R.id.tvNetworkCount)
        tvHighRisk = findViewById(R.id.tvHighRisk)

        loadAutostarts()
    }

    private fun loadAutostarts() {
        lifecycleScope.launch {
            swipeRefresh.isRefreshing = true
            try {
                val items = withContext(Dispatchers.IO) {
                    AutostartEngine(this@AutostartActivity).getAutostartApps()
                }

                // Статистика
                tvBootCount.text = items.count { it.category == AutostartCategory.BOOT }.toString()
                tvSmsCount.text = items.count { it.category == AutostartCategory.SMS }.toString()
                tvNetworkCount.text = items.count { it.category == AutostartCategory.NETWORK }.toString()
                tvHighRisk.text = items.count {
                    it.riskLevel == RiskLevel.HIGH || it.riskLevel == RiskLevel.CRITICAL
                }.toString()

                recycler.adapter = AutostartAdapter(items) { item ->
                    showDetail(item)
                }
            } catch (e: Exception) { }
            finally {
                swipeRefresh.isRefreshing = false
            }
        }
    }

    private fun showDetail(item: AutostartItem) {
        val msg = buildString {
            append("Пакет: ${item.packageName}\n")
            append("Приёмник: ${item.receiverName}\n")
            append("Действие: ${item.action}\n")
            append("Категория: ${item.category.name}\n")
            append("Приоритет: ${item.priority}\n")
            append("Системное: ${if (item.isSystemApp) "Да" else "Нет"}\n")
            append("Включено: ${if (item.isEnabled) "Да" else "Нет"}\n")
            append("Уровень риска: ${item.riskLevel.name}\n")
        }

        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle(item.appName)
            .setMessage(msg)
            .setPositiveButton("OK", null)
            .show()
    }

    class AutostartAdapter(
        private val items: List<AutostartItem>,
        private val onClick: (AutostartItem) -> Unit
    ) : RecyclerView.Adapter<AutostartAdapter.VH>() {

        class VH(view: View) : RecyclerView.ViewHolder(view) {
            val ivIcon: ImageView = view.findViewById(R.id.ivIcon)
            val tvAppName: TextView = view.findViewById(R.id.tvAppName)
            val tvReceiver: TextView = view.findViewById(R.id.tvReceiver)
            val tvCategory: TextView = view.findViewById(R.id.tvCategory)
            val tvAction: TextView = view.findViewById(R.id.tvAction)
            val tvRiskLevel: TextView = view.findViewById(R.id.tvRiskLevel)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
            val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_autostart, parent, false)
            return VH(view)
        }

        override fun onBindViewHolder(holder: VH, position: Int) {
            val item = items[position]

            holder.tvAppName.text = item.appName
            holder.tvReceiver.text = item.receiverName.takeLast(40)
            holder.tvCategory.text = item.category.name
            holder.tvAction.text = item.action

            // Иконка
            if (item.icon != null) {
                holder.ivIcon.setImageDrawable(item.icon)
            } else {
                holder.ivIcon.setImageResource(android.R.drawable.ic_menu_set_as)
            }

            // Уровень риска
            val (text, color) = when (item.riskLevel) {
                RiskLevel.SAFE -> "✓ SAFE" to 0xFF4CAF50.toInt()
                RiskLevel.LOW -> "LOW" to 0xFF8BC34A.toInt()
                RiskLevel.MEDIUM -> "⚠ MEDIUM" to 0xFFFFC107.toInt()
                RiskLevel.HIGH -> "⚠ HIGH" to 0xFFFF9800.toInt()
                RiskLevel.CRITICAL -> "⛔ CRITICAL" to 0xFFF44336.toInt()
            }
            holder.tvRiskLevel.text = text
            holder.tvRiskLevel.setTextColor(color)
        }

        override fun getItemCount() = items.size
    }
}
