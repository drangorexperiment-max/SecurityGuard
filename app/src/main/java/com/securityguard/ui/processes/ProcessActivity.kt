package com.securityguard.ui.processes

import android.os.Bundle
import android.view.View
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.chip.Chip
import com.securityguard.R
import com.securityguard.engine.ProcessEngine
import com.securityguard.model.ProcessInfo
import com.securityguard.util.Utils
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ProcessActivity : AppCompatActivity() {

    private lateinit var recycler: RecyclerView
    private lateinit var swipeRefresh: SwipeRefreshLayout
    private lateinit var tvProcessCount: TextView
    private lateinit var tvEmpty: TextView
    private lateinit var chipAll: Chip
    private lateinit var chipUser: Chip
    private lateinit var chipSuspicious: Chip

    private var allProcesses = listOf<ProcessInfo>()
    private var currentFilter = Filter.ALL

    enum class Filter { ALL, USER, SUSPICIOUS }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_process)

        val toolbar = findViewById<MaterialToolbar>(R.id.toolbar)
        toolbar.setNavigationOnClickListener { finish() }

        recycler = findViewById(R.id.recyclerProcesses)
        recycler.layoutManager = LinearLayoutManager(this)

        swipeRefresh = findViewById(R.id.swipeRefresh)
        tvProcessCount = findViewById(R.id.tvProcessCount)
        tvEmpty = findViewById(R.id.tvEmpty)

        chipAll = findViewById(R.id.chipAll)
        chipUser = findViewById(R.id.chipUser)
        chipSuspicious = findViewById(R.id.chipSuspicious)

        chipAll.setOnClickListener { setFilter(Filter.ALL) }
        chipUser.setOnClickListener { setFilter(Filter.USER) }
        chipSuspicious.setOnClickListener { setFilter(Filter.SUSPICIOUS) }

        swipeRefresh.setColorSchemeColors(getColor(R.color.accent))
        swipeRefresh.setOnRefreshListener { loadProcesses() }

        loadProcesses()
    }

    private fun loadProcesses() {
        lifecycleScope.launch {
            swipeRefresh.isRefreshing = true
            try {
                val processes = withContext(Dispatchers.IO) {
                    ProcessEngine(this@ProcessActivity).getRunningProcesses()
                }
                allProcesses = processes
                applyFilter()
                tvProcessCount.text = "${processes.size} процессов"
            } catch (e: Exception) {
                tvEmpty.visibility = View.VISIBLE
                tvEmpty.text = "Ошибка: ${e.message}"
            } finally {
                swipeRefresh.isRefreshing = false
            }
        }
    }

    private fun setFilter(filter: Filter) {
        currentFilter = filter
        applyFilter()
    }

    private fun applyFilter() {
        val filtered = when (currentFilter) {
            Filter.ALL -> allProcesses
            Filter.USER -> allProcesses.filter { !it.isSystem }
            Filter.SUSPICIOUS -> allProcesses.filter { it.riskScore > 30 }
        }

        recycler.adapter = ProcessAdapter(filtered) { process ->
            showProcessDetail(process)
        }

        tvEmpty.visibility = if (filtered.isEmpty()) View.VISIBLE else View.GONE
        tvEmpty.text = if (currentFilter == Filter.SUSPICIOUS)
            "Подозрительных процессов не обнаружено ✓" else "Нет данных"
    }

    private fun showProcessDetail(process: ProcessInfo) {
        val msg = buildString {
            append("PID: ${process.pid}\n")
            append("PPID: ${process.ppid}\n")
            append("UID: ${process.uid}\n")
            append("CPU: ${"%.1f".format(process.cpuUsage)}%\n")
            append("Память: ${Utils.formatSize(process.memoryUsage)}\n")
            append("Потоки: ${process.threads}\n")
            append("Открытые файлы: ${process.isOpenFiles}\n")
            append("Сетевые соединения: ${process.networkConnections}\n")
            append("Состояние: ${process.state}\n")
            append("Системный: ${if (process.isSystem) "Да" else "Нет"}\n")
            append("Риск: ${process.riskScore}/100\n")
            if (process.riskReasons.isNotEmpty()) {
                append("\nПричины риска:\n")
                process.riskReasons.forEach { append("• $it\n") }
            }
        }

        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle(process.name)
            .setMessage(msg)
            .setPositiveButton("OK", null)
            .setNegativeButton("Завершить") { _, _ ->
                ProcessEngine(this).killProcess(process.pid)
                loadProcesses()
            }
            .show()
    }

    class ProcessAdapter(
        private val items: List<ProcessInfo>,
        private val onClick: (ProcessInfo) -> Unit
    ) : RecyclerView.Adapter<ProcessAdapter.VH>() {

        class VH(view: View) : RecyclerView.ViewHolder(view) {
            val ivIcon: ImageView = view.findViewById(R.id.ivIcon)
            val tvName: TextView = view.findViewById(R.id.tvName)
            val tvPackage: TextView = view.findViewById(R.id.tvPackage)
            val tvCpu: TextView = view.findViewById(R.id.tvCpu)
            val tvMemory: TextView = view.findViewById(R.id.tvMemory)
            val tvThreads: TextView = view.findViewById(R.id.tvThreads)
            val tvPid: TextView = view.findViewById(R.id.tvPid)
            val tvRiskBadge: TextView = view.findViewById(R.id.tvRiskBadge)
            val tvRiskReasons: TextView = view.findViewById(R.id.tvRiskReasons)
        }

        override fun onCreateViewHolder(parent: android.view.ViewGroup, viewType: Int): VH {
            val view = android.view.LayoutInflater.from(parent.context)
                .inflate(R.layout.item_process, parent, false)
            return VH(view)
        }

        override fun onBindViewHolder(holder: VH, position: Int) {
            val proc = items[position]
            holder.tvName.text = proc.name.take(50)
            holder.tvPackage.text = proc.packageName.ifEmpty { "PID ${proc.pid}" }
            holder.tvCpu.text = "CPU: ${"%.1f".format(proc.cpuUsage)}%"
            holder.tvMemory.text = "RAM: ${Utils.formatSize(proc.memoryUsage)}"
            holder.tvThreads.text = "T:${proc.threads}"
            holder.tvPid.text = "PID:${proc.pid}"

            if (proc.riskScore > 30) {
                holder.tvRiskBadge.visibility = View.VISIBLE
                holder.tvRiskBadge.text = "⚠ ${proc.riskScore}"
                holder.tvRiskBadge.setTextColor(Utils.getRiskColor(proc.riskScore))

                if (proc.riskReasons.isNotEmpty()) {
                    holder.tvRiskReasons.visibility = View.VISIBLE
                    holder.tvRiskReasons.text = proc.riskReasons.take(2).joinToString("; ")
                }
            } else {
                holder.tvRiskBadge.visibility = View.GONE
                holder.tvRiskReasons.visibility = View.GONE
            }

            // System icon
            if (proc.isSystem) {
                holder.ivIcon.setImageResource(android.R.drawable.ic_lock_lock)
            } else {
                holder.ivIcon.setImageResource(android.R.drawable.ic_menu_manage)
            }

            holder.itemView.setOnClickListener { onClick(proc) }
        }

        override fun getItemCount() = items.size
    }
}
