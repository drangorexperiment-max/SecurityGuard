package com.securityguard.ui.permissions

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.appbar.MaterialToolbar
import com.securityguard.R
import com.securityguard.util.Utils
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class PermissionActivity : AppCompatActivity() {

    data class PermissionGroup(
        val permission: String,
        val shortName: String,
        val apps: List<String>,
        val isDangerous: Boolean,
        val isCritical: Boolean
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_permissions)

        val toolbar = findViewById<com.google.android.material.appbar.MaterialToolbar>(R.id.toolbar)
        toolbar.setNavigationOnClickListener { finish() }

        loadPermissions()
    }

    private fun loadPermissions() {
        lifecycleScope.launch {
            try {
                val groups = withContext(Dispatchers.IO) {
                    val pm = packageManager
                    val packages = pm.getInstalledPackages(
                        android.content.pm.PackageManager.GET_PERMISSIONS
                    )

                    // Группируем опасные разрешения по приложениям
                    val permMap = mutableMapOf<String, MutableList<String>>()
                    for (pkg in packages) {
                        if (Utils.isSystemApp(pkg.applicationInfo)) continue
                        val perms = pkg.requestedPermissions?.toList() ?: continue

                        for (perm in perms) {
                            if (perm in Utils.DANGEROUS_PERMISSIONS) {
                                permMap.getOrPut(perm) { mutableListOf() }
                                    .add(pkg.packageName)
                            }
                        }
                    }

                    permMap.map { (perm, apps) ->
                        PermissionGroup(
                            permission = perm,
                            shortName = perm.substringAfterLast("."),
                            apps = apps,
                            isDangerous = perm in Utils.DANGEROUS_PERMISSIONS,
                            isCritical = perm in Utils.CRITICAL_PERMISSIONS
                        )
                    }.sortedWith(compareByDescending<PermissionGroup> { it.isCritical }
                        .thenByDescending { it.apps.size })
                }

                val recycler = findViewById<RecyclerView>(R.id.recyclerPermissions)
                recycler.layoutManager = LinearLayoutManager(this@PermissionActivity)
                recycler.adapter = PermissionAdapter(groups)

                if (groups.isEmpty()) {
                    findViewById<TextView>(R.id.tvEmpty).visibility = View.VISIBLE
                }
            } catch (e: Exception) { }
        }
    }

    class PermissionAdapter(private val items: List<PermissionGroup>) :
        RecyclerView.Adapter<PermissionAdapter.VH>() {

        class VH(view: View) : RecyclerView.ViewHolder(view) {
            val tvPermName: TextView = view.findViewById(R.id.tvPermName)
            val tvPermFull: TextView = view.findViewById(R.id.tvPermFull)
            val tvAppCount: TextView = view.findViewById(R.id.tvAppCount)
            val tvSeverity: TextView = view.findViewById(R.id.tvSeverity)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
            val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_permission, parent, false)
            return VH(view)
        }

        override fun onBindViewHolder(holder: VH, position: Int) {
            val item = items[position]
            holder.tvPermName.text = item.shortName
            holder.tvPermFull.text = item.permission
            holder.tvAppCount.text = "${item.apps.size} приложений"

            if (item.isCritical) {
                holder.tvSeverity.text = "⛔ КРИТИЧЕСКОЕ"
                holder.tvSeverity.setTextColor(0xFFF44336.toInt())
            } else {
                holder.tvSeverity.text = "⚠ Опасное"
                holder.tvSeverity.setTextColor(0xFFFF9800.toInt())
            }
        }

        override fun getItemCount() = items.size
    }
}
