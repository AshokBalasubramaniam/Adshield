package com.adshield.dns

import com.adshield.domain.model.AllowReason
import com.adshield.domain.model.BlockMode
import com.adshield.domain.model.FilterDecision
import com.adshield.engine.AdFilteringEngine
import kotlinx.coroutines.withTimeoutOrNull

/** Receives one callback per processed query. Implementations must be cheap and thread-safe. */
fun interface DnsEventSink {
    fun onQuery(event: DnsEvent)
}

class DnsEvent(
    val domain: String,
    val packageName: String?,
    val decision: FilterDecision?,
    val fromCache: Boolean,
    val failed: Boolean,
    val qtype: Int = 0,
    /** CNAME targets seen in the answer (empty if none / blocked before resolving). */
    val cnames: List<String> = emptyList(),
    /** Wall-clock time spent in the pipeline, in microseconds. */
    val micros: Long = 0,
)

/**
 * The whole DNS decision pipeline, free of Android types so it is fully unit-testable:
 * parse → normalise → filter → (blocked response | cache | upstream) → cache store.
 */
class DnsQueryProcessor(
    private val engine: AdFilteringEngine,
    private val cache: DnsCache,
    private val upstream: () -> DnsUpstream?,
    private val blockMode: () -> BlockMode,
    private val sink: DnsEventSink,
    private val upstreamTimeoutMs: Long = 6000,
) {
    /** Returns the wire response to send back, or null if the query is unusable and must be dropped. */
    suspend fun process(rawQuery: ByteArray, packageName: String?): ByteArray? {
        val started = System.nanoTime()
        val query = DnsParser.parseQuery(rawQuery) ?: return DnsResponseBuilder.formErr(rawQuery)
        if (query.opcode != 0) return DnsResponseBuilder.error(query, DnsRcode.NOTIMP)

        fun emit(decision: FilterDecision?, fromCache: Boolean, failed: Boolean, cnames: List<String> = emptyList()) =
            sink.onQuery(DnsEvent(query.name, packageName, decision, fromCache, failed, query.type, cnames, (System.nanoTime() - started) / 1000))

        val decision = engine.evaluate(query.name, packageName)
        if (decision is FilterDecision.Block) {
            emit(decision, fromCache = false, failed = false)
            return DnsResponseBuilder.blocked(query, blockMode())
        }

        cache.lookup(query)?.let { hit ->
            val cloaked = blockedByCname(decision, hit.cnames, packageName)
            if (cloaked != null) {
                emit(cloaked, fromCache = true, failed = false, cnames = hit.cnames)
                return DnsResponseBuilder.blocked(query, blockMode())
            }
            emit(decision, fromCache = true, failed = false, cnames = hit.cnames)
            return hit.response
        }

        val resolver = upstream()
        val response = if (resolver == null) null else withTimeoutOrNull(upstreamTimeoutMs) { resolver.resolve(rawQuery) }
        if (response == null) {
            emit(decision, fromCache = false, failed = true)
            return DnsResponseBuilder.error(query, DnsRcode.SERVFAIL)
        }
        val cnames = DnsParser.cnameTargets(response)
        cache.put(query, response, cnames)
        val cloaked = blockedByCname(decision, cnames, packageName)
        if (cloaked != null) {
            emit(cloaked, fromCache = false, failed = false, cnames = cnames)
            return DnsResponseBuilder.blocked(query, blockMode())
        }
        emit(decision, fromCache = false, failed = false, cnames = cnames)
        return response
    }

    /**
     * CNAME-aware filtering: a clean-looking name that is an alias for a listed ad/tracker host ("CNAME cloaking")
     * is blocked. Only applied when the queried name matched nothing at all: names protected as essential, or
     * explicitly allowed by the user, are never second-guessed through their aliases.
     */
    private fun blockedByCname(decision: FilterDecision, cnames: List<String>, pkg: String?): FilterDecision.Block? {
        if (cnames.isEmpty() || decision != FilterDecision.Allow(AllowReason.NO_MATCH)) return null
        for (target in cnames) {
            val d = engine.evaluate(target, pkg)
            if (d is FilterDecision.Block) return d.copy(viaCname = target)
        }
        return null
    }
}
