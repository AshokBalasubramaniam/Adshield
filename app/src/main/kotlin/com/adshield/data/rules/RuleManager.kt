package com.adshield.data.rules

import android.content.Context
import android.util.Log
import com.adshield.data.db.BlocklistDao
import com.adshield.data.db.BlocklistEntity
import com.adshield.data.db.UserRuleDao
import com.adshield.data.settings.SettingsRepository
import com.adshield.domain.model.BlockCategory
import com.adshield.domain.model.EngineStatus
import com.adshield.engine.AdFilteringEngine
import com.adshield.engine.DomainNormalizer
import com.adshield.engine.DomainSet
import com.adshield.engine.RuleParser
import com.adshield.engine.RuleSnapshot
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.File
import java.io.IOException
import java.util.EnumMap
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

data class UpdateOutcome(val id: String, val name: String, val result: DownloadResult?)

@Singleton
class RuleManager @Inject constructor(
    @ApplicationContext private val context: Context,
    private val engine: AdFilteringEngine,
    private val blocklistDao: BlocklistDao,
    private val userRuleDao: UserRuleDao,
    private val settings: SettingsRepository,
) {
    private val mutex = Mutex()
    private val _status = MutableStateFlow(EngineStatus())
    val status: StateFlow<EngineStatus> = _status.asStateFlow()

    val downloader = ListDownloader(File(context.filesDir, "blocklists"))

    suspend fun ensureSeeded() {
        BuiltInLists.all.forEach { blocklistDao.insertIfAbsent(it) }
    }

    /** Rebuilds the in-memory rule snapshot from enabled lists and user rules. */
    suspend fun reload() = mutex.withLock {
        _status.value = _status.value.copy(loading = true)
        try {
            ensureSeeded()
            val snapshot = withContext(Dispatchers.Default) { buildSnapshot() }
            engine.update(snapshot)
            _status.value = EngineStatus(
                loaded = true, domainCount = snapshot.listDomainCount,
                loadedAtMillis = snapshot.loadedAtMillis, loading = false,
            )
        } catch (e: IOException) {
            Log.w(TAG, "Rule load failed", e)
            _status.value = _status.value.copy(loading = false, lastError = e.message)
            throw e
        }
    }

    private suspend fun buildSnapshot(): RuleSnapshot {
        val builders = EnumMap<BlockCategory, DomainSet.Builder>(BlockCategory::class.java)
        for (src in blocklistDao.getAll()) {
            if (!src.enabled) continue
            val category = runCatching { BlockCategory.valueOf(src.category) }.getOrDefault(BlockCategory.ADS)
            val builder = builders.getOrPut(category) { DomainSet.Builder(4096) }
            val accepted = openSource(src)?.use { reader -> RuleParser.parse(reader) { builder.add(it) }.accepted } ?: continue
            if (src.domainCount != accepted) blocklistDao.setCount(src.id, accepted)
        }

        val allow = DomainSet.Builder()
        val block = DomainSet.Builder()
        val perApp = HashMap<String, DomainSet.Builder>()
        for (rule in userRuleDao.getAll()) {
            val d = DomainNormalizer.normalizeRuleDomain(rule.domain) ?: continue
            when {
                !rule.isAllow -> block.add(d)
                rule.packageName.isEmpty() -> allow.add(d)
                else -> perApp.getOrPut(rule.packageName) { DomainSet.Builder() }.add(d)
            }
        }
        return RuleSnapshot(
            categorySets = builders.mapValues { it.value.build() },
            userBlock = block.build(),
            userAllowGlobal = allow.build(),
            userAllowByApp = perApp.mapValues { it.value.build() },
            loadedAtMillis = System.currentTimeMillis(),
            protectStreamingFirstParty = settings.dns.first().protectStreamingFirstParty,
        )
    }

    /** Opens a source for reading, verifying the integrity of downloaded files. Returns null when unavailable. */
    private suspend fun openSource(src: BlocklistEntity): BufferedReader? {
        if (src.url == null) {
            return try {
                context.assets.open("blocklists/${src.id}.txt").bufferedReader()
            } catch (e: IOException) {
                Log.w(TAG, "Missing bundled list ${src.id}", e)
                null
            }
        }
        val file = downloader.fileFor(src.id)
        if (!file.exists()) return null
        val expected = src.sha256
        if (expected == null || ListDownloader.sha256Of(file) != expected) {
            Log.w(TAG, "Integrity check failed for ${src.id}; discarding cached file")
            file.delete()
            blocklistDao.clearDownload(src.id)
            blocklistDao.setError(src.id, "Cached file failed its integrity check and was discarded. Update the list again.")
            return null
        }
        return file.bufferedReader()
    }

    /** Emits whenever anything that affects filtering changes (debounced). */
    @OptIn(FlowPreview::class)
    fun changes(): Flow<Unit> = combine(
        blocklistDao.observeAll().map { list -> list.map { Triple(it.id, it.enabled, it.sha256) } },
        userRuleDao.observeAll(),
        settings.dns.map { it.protectStreamingFirstParty },
    ) { a, b, c -> Triple(a, b, c) }
        .distinctUntilChanged()
        .debounce(400)
        .map { }

    suspend fun updateAll(force: Boolean): List<UpdateOutcome> {
        ensureSeeded()
        val now = System.currentTimeMillis()
        fun isDue(src: BlocklistEntity) = force || now - src.updatedAt > MIN_AUTO_INTERVAL_MS
        val targets = blocklistDao.getAll().filter { it.url != null && it.enabled && isDue(it) }
        val outcomes = targets.map { update(it) }
        if (outcomes.any { it.result is DownloadResult.Success }) reload()
        return outcomes
    }

    suspend fun updateOne(id: String): UpdateOutcome? {
        val src = blocklistDao.get(id) ?: return null
        val outcome = update(src)
        if (outcome.result is DownloadResult.Success) reload()
        return outcome
    }

    private suspend fun update(src: BlocklistEntity): UpdateOutcome {
        val url = src.url ?: return UpdateOutcome(src.id, src.name, null)
        val result = downloader.download(src.id, url, src.domainCount)
        when (result) {
            is DownloadResult.Success -> blocklistDao.markUpdated(src.id, result.sha256, result.domainCount, System.currentTimeMillis())
            is DownloadResult.Failure -> blocklistDao.setError(src.id, result.reason)
        }
        return UpdateOutcome(src.id, src.name, result)
    }

    /** Adds a user-supplied list URL. Returns an error message, or null on success. */
    suspend fun addCustomList(name: String, url: String, category: BlockCategory): String? {
        val trimmed = url.trim()
        if (ListDownloader.parseAllowedUrl(trimmed) == null) return "Enter a valid https:// URL"
        if (name.isBlank()) return "Enter a name"
        val id = "custom-" + UUID.randomUUID().toString().take(8)
        blocklistDao.upsert(
            BlocklistEntity(
                id = id, name = name.trim().take(60), description = "Custom list added by you", url = trimmed,
                category = category.name, enabled = true, builtIn = false, license = "Unknown (user supplied)", sortOrder = 100,
            ),
        )
        val outcome = updateOne(id)
        val failure = (outcome?.result as? DownloadResult.Failure)?.reason
        if (failure != null) {
            blocklistDao.deleteCustom(id)
            return failure
        }
        return null
    }

    suspend fun removeCustomList(id: String) {
        blocklistDao.deleteCustom(id)
        downloader.fileFor(id).delete()
        reload()
    }

    private companion object {
        const val TAG = "RuleManager"
        const val MIN_AUTO_INTERVAL_MS = 12L * 60 * 60 * 1000
    }
}
