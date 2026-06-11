package com.securityguard.ui.network

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout
import com.google.android.material.appbar.MaterialToolbar
import com.securityguard.R
import com.securityguard.engine.NetworkEngine
import com.securityguard.model.NetworkConnection
import com.securityguard.util.Utils
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class NetworkActivity : AppCompatActivity() {

    private lateinit var recycler: RecyclerView
    private lateinit var swipeRefresh: SwipeRefreshLayout
    private lateinit var tvTotal: TextView
    private lateinit var tvEstablished: TextView
    private lateinit var tvSuspicious: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_network)

        val toolbar = findViewById<MaterialToolbar>(R.id.toolbar)
        toolbar.setNavigationOnClickListener { finish() }

        recycler = findViewById(R.id.recyclerConnections)
        recycler.layoutManager = LinearLayoutManager(this)

        swipeRefresh = findViewById(R.id.swipeRefresh)
        swipeRefresh.setColorSchemeColors(getColor(R.color.accent))
        swipeRefresh.setOnRefreshListener { loadConnections() }

        tvTotal = findViewById(R.id.tvTotalConn)
        tvEstablished = findViewById(R.id.tvEstablished)
        tvSuspicious = findViewById(R.id.tvSuspiciousConn)

        loadConnections()
    }

    private fun loadConnections() {
        lifecycleScope.launch {
            swipeRefresh.isRefreshing = true
            try {
                val stats = withContext(Dispatchers.IO) {
                    NetworkEngine(this@NetworkActivity).getNetworkStats()
                }

                tvTotal.text = stats.totalConnections.toString()
                tvEstablished.text = stats.establishedConnections.toString()
                tvSuspicious.text = stats.suspiciousConnections.toString()

                // Сортируем: подозрительные первыми, затем established
                val sorted = stats.connections.sortedWith(
                    compareByDescending<NetworkConnection> { it.isSuspicious }
                        .thenByDescending { it.isEstablished }
                )

                recycler.adapter = ConnectionAdapter(sorted)
            } catch (e: Exception) {
                tvTotal.text = "?"
            } finally {
                swipeRefresh.isRefreshing = false
            }
        }
    }

    class ConnectionAdapter(private val items: List<NetworkConnection>) :
        RecyclerView.Adapter<ConnectionAdapter.VH>() {

        class VH(view: View) : RecyclerView.ViewHolder(view) {
            val tvAppName: TextView = view.findViewById(R.id.tvAppName)
            val tvProtocol: TextView = view.findViewById(R.id.tvProtocol)
            val tvRemoteAddress: TextView = view.findViewById(R.id.tvRemoteAddress)
            val tvState: TextView = view.findViewById(R.id.tvState)
            val tvRiskWarning: TextView = view.findViewById(R.id.tvRiskWarning)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
            val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_connection, parent, false)
            return VH(view)
        }

        override fun onBindViewHolder(holder: VH, position: Int) {
            val conn = items[position]

            holder.tvAppName.text = conn.appName
            holder.tvProtocol.text = conn.protocol
            holder.tvRemoteAddress.text = "${conn.remoteAddress}:${conn.remotePort}"
            holder.tvState.text = conn.state

            // Цвет состояния
            holder.tvState.setTextColor(
                when {
                    conn.isEstablished -> holder.itemView.context.getColor(R.color.safe)
                    conn.state == "LISTEN" -> holder.itemView.context.getColor(R.color.info)
                    else -> holder.itemView.context.getColor(R.color.text_hint)
                }
            )

            // Предупреждение
            if (conn.isSuspicious) {
                holder.tvRiskWarning.visibility = View.VISIBLE
                holder.tvRiskWarning.text = "⚠ ${conn.riskReasons.joinToString(", ").take(50)}"
                holder.tvAppName.setTextColor(
                    holder.itemView.context.getColor(R.color.danger)
                )
            } else {
                holder.tvRiskWarning.visibility = View.GONE
            }
        }

        override fun getItemCount() = items.size
    }
}
