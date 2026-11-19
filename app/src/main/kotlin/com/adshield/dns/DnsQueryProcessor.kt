package com.adshield.dns

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
        val query = DnsParser.parseQuery(rawQuery) ?: return DnsResponseBuilder.formErr(rawQuery)
        if (query.opcode != 0) return DnsResponseBuilder.error(query, DnsRcode.NOTIMP)

        val decision = engine.evaluate(query.name, packageName)
        if (decision is FilterDecision.Block) {
            sink.onQuery(DnsEvent(query.name, packageName, decision, fromCache = false, failed = false))
            return DnsResponseBuilder.blocked(query, blockMode())
        }

        cache.get(query)?.let {
            sink.onQuery(DnsEvent(query.name, packageName, decision, fromCache = true, failed = false))
            return it
        }

        val resolver = upstream()
        val response = if (resolver == null) null else withTimeoutOrNull(upstreamTimeoutMs) { resolver.resolve(rawQuery) }
        if (response == null) {
            sink.onQuery(DnsEvent(query.name, packageName, decision, fromCache = false, failed = true))
            return DnsResponseBuilder.error(query, DnsRcode.SERVFAIL)
        }
        cache.put(query, response)
        sink.onQuery(DnsEvent(query.name, packageName, decision, fromCache = false, failed = false))
        return response
    }
}
