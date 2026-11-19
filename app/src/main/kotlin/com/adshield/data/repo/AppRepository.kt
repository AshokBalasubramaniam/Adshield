package com.adshield.data.repo

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
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

    class PackageDetails(val versionName: String?, val versionCode: Long, val isSystemApp: Boolean, val installerPackage: String?)

    /** Version and provenance of an installed package (null if not installed / not visible). */
    fun details(pkg: String): PackageDetails? = try {
        val pm = context.packageManager
        val info = pm.getPackageInfo(pkg, 0)
        val flags = info.applicationInfo?.flags ?: 0
        val system = flags and (android.content.pm.ApplicationInfo.FLAG_SYSTEM or android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
        val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            runCatching { pm.getInstallSourceInfo(pkg).installingPackageName }.getOrNull()
        } else {
            @Suppress("DEPRECATION")
            runCatching { pm.getInstallerPackageName(pkg) }.getOrNull()
        }
        PackageDetails(info.versionName, info.longVersionCode, system, installer)
    } catch (_: PackageManager.NameNotFoundException) {
        null
    }

    fun labelOf(pkg: String): String = runCatching {
        val pm = context.packageManager
        pm.getApplicationInfo(pkg, 0).loadLabel(pm).toString()
    }.getOrDefault(pkg)
}
