package com.adshield.data.repo

import com.adshield.data.db.StatsDao
import com.adshield.dns.DnsEvent
import com.adshield.dns.DnsEventSink
import com.adshield.domain.model.AppStat
import com.adshield.domain.model.BlockCategory
import com.adshield.domain.model.DayStat
import com.adshield.domain.model.FilterDecision
import com.adshield.domain.model.StatsTotals
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import java.time.LocalDate
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import javax.inject.Inject
import javax.inject.Singleton

data class RecentBlock(val domain: String, val category: BlockCategory, val atMillis: Long)

/**
 * Counters are accumulated in memory on the DNS hot path (a few atomic increments per query, no I/O)
 * and written to the local Room database in batches by [flush]. Everything stays on the device.
 * Only counts are persisted — never domains, never which app asked for what.
 */
@Singleton
class StatsRepository @Inject constructor(private val dao: StatsDao) : DnsEventSink {
    private class AppDelta {
        val total = AtomicLong()
        val blocked = AtomicLong()
    }

    private val total = AtomicLong()
    private val allowed = AtomicLong()
    private val cacheHits = AtomicLong()
    private val failures = AtomicLong()
    private val byCategory = BlockCategory.entries.associateWith { AtomicLong() }
    private val perApp = ConcurrentHashMap<String, AppDelta>()
    @Volatile private var dirty = false

    /** In-memory only (never written to disk), cleared when protection stops or stats are reset. */
    private val recent = ArrayDeque<RecentBlock>()
    private val _recentBlocks = MutableStateFlow<List<RecentBlock>>(emptyList())
    val recentBlocks: StateFlow<List<RecentBlock>> = _recentBlocks.asStateFlow()

    override fun onQuery(event: DnsEvent) {
        total.incrementAndGet()
        val blocked = event.decision is FilterDecision.Block
        when {
            event.failed -> failures.incrementAndGet()
            blocked -> byCategory.getValue((event.decision as FilterDecision.Block).category).incrementAndGet()
            else -> allowed.incrementAndGet()
        }
        if (event.fromCache) cacheHits.incrementAndGet()
        val app = perApp.getOrPut(event.packageName.orEmpty()) { AppDelta() }
        app.total.incrementAndGet()
        if (blocked) app.blocked.incrementAndGet()
        if (blocked) {
            val d = event.decision as FilterDecision.Block
            synchronized(recent) {
                recent.addFirst(RecentBlock(event.domain, d.category, System.currentTimeMillis()))
                while (recent.size > RECENT_MAX) recent.removeLast()
            }
        }
        dirty = true
    }

    /** Persists pending deltas. Cheap no-op when nothing happened. */
    suspend fun flush() {
        if (!dirty) return
        dirty = false
        val t = total.getAndSet(0)
        val a = allowed.getAndSet(0)
        val c = cacheHits.getAndSet(0)
        val f = failures.getAndSet(0)
        val cats = byCategory.mapValues { it.value.getAndSet(0) }
        val blockedNow = cats.values.sum()
        if (t != 0L) dao.addCounter("total", t)
        if (a != 0L) dao.addCounter("allowed", a)
        if (c != 0L) dao.addCounter("cache", c)
        if (f != 0L) dao.addCounter("fail", f)
        cats.forEach { (cat, n) -> if (n != 0L) dao.addCounter(cat.name.lowercase(), n) }
        for ((pkg, delta) in perApp) {
            val dt = delta.total.getAndSet(0)
            val db = delta.blocked.getAndSet(0)
            if (dt != 0L || db != 0L) dao.addAppCounter(pkg, dt, db)
        }
        if (t != 0L) dao.addDaily(LocalDate.now().toEpochDay(), t, blockedNow)
        synchronized(recent) { _recentBlocks.value = recent.toList() }
    }

    fun clearRecent() {
        synchronized(recent) { recent.clear() }
        _recentBlocks.value = emptyList()
    }

    suspend fun pruneOld() = dao.pruneDaily(LocalDate.now().toEpochDay() - RETENTION_DAYS)

    suspend fun reset() {
        total.set(0); allowed.set(0); cacheHits.set(0); failures.set(0)
        byCategory.values.forEach { it.set(0) }
        perApp.clear()
        dirty = false
        clearRecent()
        dao.resetAll()
    }

    val totals: Flow<StatsTotals> = dao.observeCounters().map { rows ->
        val m = rows.associate { it.key to it.value }
        StatsTotals(
            totalQueries = m["total"] ?: 0, allowed = m["allowed"] ?: 0, cacheHits = m["cache"] ?: 0, failures = m["fail"] ?: 0,
            ads = m["ads"] ?: 0, trackers = m["tracker"] ?: 0, malware = m["malware"] ?: 0,
            phishing = m["phishing"] ?: 0, custom = m["custom"] ?: 0,
        )
    }

    fun topApps(limit: Int = 20): Flow<List<AppStat>> =
        dao.observeTopApps(limit).map { l -> l.map { AppStat(it.packageName, it.total, it.blocked) } }

    fun lastDays(days: Int = 7): Flow<List<DayStat>> =
        dao.observeDays(LocalDate.now().toEpochDay() - (days - 1)).map { l -> l.map { DayStat(it.epochDay, it.total, it.blocked) } }

    private companion object {
        const val RECENT_MAX = 50
        const val RETENTION_DAYS = 30L
    }
}
