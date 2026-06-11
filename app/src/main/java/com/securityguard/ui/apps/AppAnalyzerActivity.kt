package com.securityguard.ui.apps

import android.content.Intent
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
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
import com.google.android.material.chip.Chip
import com.google.android.material.textfield.TextInputEditText
import com.securityguard.R
import com.securityguard.util.Utils
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class AppAnalyzerActivity : AppCompatActivity() {

    private lateinit var recycler: RecyclerView
    private lateinit var swipeRefresh: SwipeRefreshLayout
    private lateinit var etSearch: TextInputEditText

    private var allApps = listOf<AppData>()
    private var currentFilter = AppFilter.ALL

    enum class AppFilter { ALL, USER, SYSTEM, DANGEROUS, WITH_PERMS }

    data class AppData(
        val packageName: String,
        val appName: String,
        val icon: android.graphics.drawable.Drawable?,
        val isSystemApp: Boolean,
        val dangerousPerms: Int,
        val criticalPerms: Int,
        val riskScore: Int,
        val apkSize: Long,
        val versionName: String,
        val targetSdk: Int
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_app_analyzer)

        val toolbar = findViewById<MaterialToolbar>(R.id.toolbar)
        toolbar.setNavigationOnClickListener { finish() }

        recycler = findViewById(R.id.recyclerApps)
        recycler.layoutManager = LinearLayoutManager(this)

        swipeRefresh = findViewById(R.id.swipeRefresh)
        swipeRefresh.setColorSchemeColors(getColor(R.color.accent))
        swipeRefresh.setOnRefreshListener { loadApps() }

        etSearch = findViewById(R.id.etSearch)
        etSearch.addTextChangedListener(object : TextWatcher {
            override fun afterTextChanged(s: Editable?) { applyFilter() }
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
        })

        findViewById<Chip>(R.id.chipAllApps).setOnClickListener { setFilter(AppFilter.ALL) }
        findViewById<Chip>(R.id.chipUserApps).setOnClickListener { setFilter(AppFilter.USER) }
        findViewById<Chip>(R.id.chipSystemApps).setOnClickListener { setFilter(AppFilter.SYSTEM) }
        findViewById<Chip>(R.id.chipDangerous).setOnClickListener { setFilter(AppFilter.DANGEROUS) }
        findViewById<Chip>(R.id.chipWithPerm).setOnClickListener { setFilter(AppFilter.WITH_PERMS) }

        loadApps()
    }

    private fun loadApps() {
        lifecycleScope.launch {
            swipeRefresh.isRefreshing = true
            try {
                val apps = withContext(Dispatchers.IO) {
                    val pm = packageManager
                    val packages = pm.getInstalledPackages(
                        android.content.pm.PackageManager.GET_PERMISSIONS
                    )
                    packages.mapNotNull { pkg ->
                        try {
                            val appInfo = pkg.applicationInfo
                            val perms = pkg.requestedPermissions?.toList() ?: emptyList()
                            val dangerous = perms.count { it in Utils.DANGEROUS_PERMISSIONS }
                            val critical = perms.count { it in Utils.CRITICAL_PERMISSIONS }

                            val risk = Utils.calculatePermissionRisk(
                                perms.filter { it in Utils.DANGEROUS_PERMISSIONS },
                                perms.filter { it in Utils.CRITICAL_PERMISSIONS }
                            )

                            val apkFile = java.io.File(appInfo.sourceDir)

                            AppData(
                                packageName = pkg.packageName,
                                appName = pm.getApplicationLabel(appInfo).toString(),
                                icon = pm.getApplicationIcon(appInfo),
                                isSystemApp = Utils.isSystemApp(appInfo),
                                dangerousPerms = dangerous,
                                criticalPerms = critical,
                                riskScore = risk,
                                apkSize = if (apkFile.exists()) apkFile.length() else 0,
                                versionName = pkg.versionName ?: "",
                                targetSdk = appInfo.targetSdkVersion
                            )
                        } catch (e: Exception) { null }
                    }.sortedByDescending { it.riskScore }
                }

                allApps = apps
                applyFilter()
            } catch (e: Exception) { }
            finally {
                swipeRefresh.isRefreshing = false
            }
        }
    }

    private fun setFilter(filter: AppFilter) {
        currentFilter = filter
        applyFilter()
    }

    private fun applyFilter() {
        val query = etSearch.text?.toString()?.lowercase() ?: ""
        val filtered = allApps.filter { app ->
            val matchesFilter = when (currentFilter) {
                AppFilter.ALL -> true
                AppFilter.USER -> !app.isSystemApp
                AppFilter.SYSTEM -> app.isSystemApp
                AppFilter.DANGEROUS -> app.riskScore > 40
                AppFilter.WITH_PERMS -> app.criticalPerms > 0
            }
            val matchesSearch = query.isEmpty() ||
                app.appName.lowercase().contains(query) ||
                app.packageName.lowercase().contains(query)

            matchesFilter && matchesSearch
        }

        recycler.adapter = AppAdapter(filtered) { app ->
            val intent = Intent(this, AppDetailActivity::class.java)
            intent.putExtra("package_name", app.packageName)
            startActivity(intent)
        }
    }

    class AppAdapter(
        private val items: List<AppData>,
        private val onClick: (AppData) -> Unit
    ) : RecyclerView.Adapter<AppAdapter.VH>() {

        class VH(view: View) : RecyclerView.ViewHolder(view) {
            val ivIcon: ImageView = view.findViewById(R.id.ivIcon)
            val tvAppName: TextView = view.findViewById(R.id.tvAppName)
            val tvPackageName: TextView = view.findViewById(R.id.tvPackageName)
            val tvDangerPerms: TextView = view.findViewById(R.id.tvDangerPerms)
            val tvApkSize: TextView = view.findViewById(R.id.tvApkSize)
            val tvRiskScore: TextView = view.findViewById(R.id.tvRiskScore)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
            val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_app, parent, false)
            return VH(view)
        }

        override fun onBindViewHolder(holder: VH, position: Int) {
            val app = items[position]

            holder.tvAppName.text = app.appName
            holder.tvPackageName.text = app.packageName
            holder.tvApkSize.text = Utils.formatSize(app.apkSize)

            if (app.dangerousPerms > 0) {
                holder.tvDangerPerms.text = "${app.dangerousPerms} опасных / ${app.criticalPerms} крит."
                holder.tvDangerPerms.setTextColor(Utils.getRiskColor(app.riskScore))
            } else {
                holder.tvDangerPerms.text = "Безопасные права"
                holder.tvDangerPerms.setTextColor(0xFF4CAF50.toInt())
            }

            holder.tvRiskScore.text = app.riskScore.toString()
            holder.tvRiskScore.setTextColor(Utils.getRiskColor(app.riskScore))

            if (app.icon != null) {
                holder.ivIcon.setImageDrawable(app.icon)
            }

            holder.itemView.setOnClickListener { onClick(app) }
        }

        override fun getItemCount() = items.size
    }
}
