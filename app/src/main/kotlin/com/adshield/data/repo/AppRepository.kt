package com.adshield.data.repo

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import com.adshield.data.db.AppSettingDao
import com.adshield.data.db.AppSettingEntity
import com.adshield.domain.model.InstalledApp
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Lists apps that have a launcher entry. Visibility comes from a narrowly-scoped `<queries>` intent
 * declaration in the manifest, so no QUERY_ALL_PACKAGES permission is needed.
 */
@Singleton
class AppRepository @Inject constructor(
    @ApplicationContext private val context: Context,
    private val dao: AppSettingDao,
) {
    val disabledPackages: Flow<Set<String>> = dao.observeDisabled().map { it.toSet() }

    suspend fun launchableApps(): List<InstalledApp> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val disabled = dao.getDisabled().toSet()
        val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        pm.queryIntentActivities(intent, 0)
            .asSequence()
            .map { it.activityInfo.packageName }
            .distinct()
            .filter { it != context.packageName }
            .mapNotNull { pkg ->
                runCatching { InstalledApp(pkg, pm.getApplicationInfo(pkg, 0).loadLabel(pm).toString(), pkg !in disabled) }.getOrNull()
            }
            .sortedBy { it.label.lowercase() }
            .toList()
    }

    suspend fun setFilteringEnabled(pkg: String, enabled: Boolean) {
        if (enabled) dao.clear(pkg) else dao.upsert(AppSettingEntity(pkg, false))
    }

    suspend fun enableAll() = dao.getDisabled().forEach { dao.clear(it) }

    fun isInstalled(pkg: String): Boolean =
        try {
            context.packageManager.getPackageInfo(pkg, 0)
            true
        } catch (_: PackageManager.NameNotFoundException) {
            false
        }

    fun labelOf(pkg: String): String = runCatching {
        val pm = context.packageManager
        pm.getApplicationInfo(pkg, 0).loadLabel(pm).toString()
    }.getOrDefault(pkg)
}
