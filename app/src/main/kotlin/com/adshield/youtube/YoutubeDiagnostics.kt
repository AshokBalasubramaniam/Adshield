package com.adshield.youtube

import android.util.Log
import com.adshield.BuildConfig
import com.adshield.dns.DnsEvent
import com.adshield.dns.DnsEventSink
import com.adshield.domain.model.AllowReason
import com.adshield.domain.model.BlockCategory
import com.adshield.domain.model.FilterDecision
import com.adshield.vpn.TunnelObserver
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import javax.inject.Inject
import javax.inject.Singleton

enum class Verdict(val label: String) {
    BLOCKED_AD("Blocked · ad list"),
    BLOCKED_TRACKER("Blocked · tracker list"),
    BLOCKED_OTHER("Blocked · malware/phishing/custom"),
    ALLOWED_ESSENTIAL("Allowed · protected as essential"),
    ALLOWED_USER("Allowed · your allow rule"),
    ALLOWED_UNLISTED("Allowed · not on any list"),
    FAILED("Upstream failed"),
    ;

    val blocked: Boolean get() = this == BLOCKED_AD || this == BLOCKED_TRACKER || this == BLOCKED_OTHER
}

data class LogEntry(
    val atMillis: Long,
    val domain: String,
    val qtype: Int,
    val cls: YoutubeClass,
    val verdict: Verdict,
    val matchedRule: String?,
    val sourceId: String?,
    val viaCname: String?,
    val cnames: List<String>,
    val fromCache: Boolean,
    val attributedPackage: String?,
    val micros: Long,
)

data class BypassSignals(
    /** Plain-DNS queries that arrived at a captured public resolver: some app hard-codes its DNS server. */
    val hardcodedResolverQueries: Long = 0,
    /** TCP connections to a captured resolver address on a non-DNS port (853 = DoT, 443 = DoH-to-IP) that were refused. */
    val refusedTcpByPort: Map<Int, Long> = emptyMap(),
    /** UDP datagrams to a captured resolver on a non-DNS port (QUIC / DNS-over-QUIC) that were dropped. */
    val droppedUdpByPort: Map<Int, Long> = emptyMap(),
) {
    val encryptedDnsAttempts: Long get() = refusedTcpByPort.values.sum() + droppedUdpByPort.values.sum()
}

data class AttributionInfo(val attributed: Int, val unattributed: Int, val systemResolverMasksApps: Boolean)

data class DiagnosticsSnapshot(
    val counts: Map<YoutubeClass, Map<Verdict, Long>>,
    val totalRelated: Long,
    val bypass: BypassSignals,
    val attribution: AttributionInfo?,
    val attributedToYoutube: Long,
) {
    fun count(cls: YoutubeClass, v: Verdict): Long = counts[cls]?.get(v) ?: 0

    /** Lookups of ad-serving domains that the filter answered locally. Lookups, not ads. */
    val adServingBlocked: Long get() = count(YoutubeClass.AD_SERVING, Verdict.BLOCKED_AD) + count(YoutubeClass.AD_SERVING, Verdict.BLOCKED_TRACKER) +
        count(YoutubeClass.AD_SERVING, Verdict.BLOCKED_OTHER)
    val trackersBlocked: Long get() = count(YoutubeClass.ANALYTICS, Verdict.BLOCKED_AD) + count(YoutubeClass.ANALYTICS, Verdict.BLOCKED_TRACKER) +
        count(YoutubeClass.ANALYTICS, Verdict.BLOCKED_OTHER)
    val allowedYoutube: Long get() = YoutubeClass.entries.filter { it.playbackCritical }.sumOf { c ->
        count(c, Verdict.ALLOWED_ESSENTIAL) + count(c, Verdict.ALLOWED_USER) + count(c, Verdict.ALLOWED_UNLISTED)
    }

    /** Playback-critical lookups that were blocked or failed: the evidence that matters for "did I break YouTube". */
    val playbackCriticalProblems: Long get() = YoutubeClass.entries.filter { it.playbackCritical }.sumOf { c ->
        Verdict.entries.filter { it.blocked || it == Verdict.FAILED }.sumOf { v -> count(c, v) }
    }
}

/**
 * Local-only, in-memory record of YouTube-related DNS decisions. Counters are real per-lookup counts
 * (never estimates); the detailed log is only recorded while [recording] is on, is bounded, and is never
 * persisted or transmitted (the user may export it explicitly). It records DNS lookups, not ads.
 */
@Singleton
class YoutubeDiagnostics @Inject constructor() : DnsEventSink, TunnelObserver {
    @Volatile var recording: Boolean = false
    @Volatile var attributionProvider: (() -> AttributionInfo)? = null

    private val counters = ConcurrentHashMap<Int, AtomicLong>() // key = class ordinal * 16 + verdict ordinal
    private val related = AtomicLong()
    private val toYoutubeApp = AtomicLong()
    private val log = ArrayDeque<LogEntry>()

    private val hardcoded = AtomicLong()
    private val refusedTcp = ConcurrentHashMap<Int, AtomicLong>()
    private val droppedUdp = ConcurrentHashMap<Int, AtomicLong>()

    override fun onQuery(event: DnsEvent) {
        val cls = YoutubeClassifier.classify(event.domain)
        if (!YoutubeClassifier.isYoutubeRelated(cls, event.packageName)) return
        val verdict = verdictOf(event)
        related.incrementAndGet()
        if (event.packageName != null && event.packageName in YoutubeClassifier.APP_PACKAGES) toYoutubeApp.incrementAndGet()
        counters.getOrPut(cls.ordinal * 16 + verdict.ordinal) { AtomicLong() }.incrementAndGet()
        if (!recording) return
        val d = event.decision as? FilterDecision.Block
        val entry = LogEntry(
            System.currentTimeMillis(), event.domain, event.qtype, cls, verdict, d?.matchedRule, d?.sourceId, d?.viaCname,
            event.cnames, event.fromCache, event.packageName, event.micros,
        )
        synchronized(log) {
            log.addFirst(entry)
            while (log.size > MAX_LOG) log.removeLast()
        }
        if (BuildConfig.DEBUG) {
            Log.d(
                TAG,
                "${verdict.name} ${cls.name} ${event.domain} type=${event.qtype} rule=${d?.matchedRule} src=${d?.sourceId} " +
                    "cname=${d?.viaCname} cache=${event.fromCache} app=${event.packageName}",
            )
        }
    }

    private fun verdictOf(e: DnsEvent): Verdict {
        if (e.failed) return Verdict.FAILED
        return when (val d = e.decision) {
            is FilterDecision.Block -> when (d.category) {
                BlockCategory.ADS -> Verdict.BLOCKED_AD
                BlockCategory.TRACKER -> Verdict.BLOCKED_TRACKER
                else -> Verdict.BLOCKED_OTHER
            }
            is FilterDecision.Allow -> when (d.reason) {
                AllowReason.ESSENTIAL -> Verdict.ALLOWED_ESSENTIAL
                AllowReason.USER_GLOBAL, AllowReason.USER_APP -> Verdict.ALLOWED_USER
                AllowReason.NO_MATCH -> Verdict.ALLOWED_UNLISTED
            }
            null -> Verdict.ALLOWED_UNLISTED
        }
    }

    override fun onHardcodedResolverQuery(resolver: ByteArray) { hardcoded.incrementAndGet() }
    override fun onRefusedTcp(dst: ByteArray, port: Int) { refusedTcp.getOrPut(port) { AtomicLong() }.incrementAndGet() }
    override fun onDroppedUdp(dst: ByteArray, port: Int) { droppedUdp.getOrPut(port) { AtomicLong() }.incrementAndGet() }

    fun snapshot(): DiagnosticsSnapshot {
        val by = YoutubeClass.entries.associateWith { c ->
            Verdict.entries.associateWith { v -> counters[c.ordinal * 16 + v.ordinal]?.get() ?: 0L }.filterValues { it > 0 }
        }.filterValues { it.isNotEmpty() }
        return DiagnosticsSnapshot(
            by, related.get(),
            BypassSignals(hardcoded.get(), refusedTcp.mapValues { it.value.get() }, droppedUdp.mapValues { it.value.get() }),
            attributionProvider?.invoke(), toYoutubeApp.get(),
        )
    }

    fun entries(): List<LogEntry> = synchronized(log) { log.toList() }

    /** Clears counters and log (called on reset and when protection stops, so nothing outlives the session). */
    fun clear() {
        counters.clear(); related.set(0); toYoutubeApp.set(0)
        hardcoded.set(0); refusedTcp.clear(); droppedUdp.clear()
        synchronized(log) { log.clear() }
    }

    private companion object {
        const val TAG = "AdShieldDiag" // debug builds only
        const val MAX_LOG = 1500
    }
}
