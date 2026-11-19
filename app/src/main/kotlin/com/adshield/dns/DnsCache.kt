package com.adshield.dns

/**
 * Bounded LRU cache of upstream DNS responses, honouring record TTLs (clamped).
 * Only NOERROR and NXDOMAIN answers are stored; failures are never cached.
 */
class DnsCache(
    private val maxEntries: Int = 2048,
    private val maxTtlSeconds: Long = 300,
    private val negativeTtlSeconds: Long = 30,
    private val nanoClock: () -> Long = System::nanoTime,
) {
    private class Entry(val response: ByteArray, val expiresAtNanos: Long)

    private val map = object : LinkedHashMap<String, Entry>(256, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Entry>?): Boolean = size > maxEntries
    }

    private fun key(query: DnsQuery) = "${query.name}/${query.type}/${query.qclass}"

    /** Returns a copy of the cached response re-addressed to [query], or null. */
    fun get(query: DnsQuery): ByteArray? {
        val entry = synchronized(map) { map[key(query)] } ?: return null
        if (nanoClock() >= entry.expiresAtNanos) {
            synchronized(map) { map.remove(key(query)) }
            return null
        }
        val out = entry.response.copyOf()
        out[0] = (query.id shr 8).toByte()
        out[1] = query.id.toByte()
        // Echo the client's exact question bytes (preserves 0x20 case randomisation).
        val qLen = query.questionEnd - DnsParser.HEADER_SIZE
        if (out.size >= DnsParser.HEADER_SIZE + qLen) {
            System.arraycopy(query.raw, DnsParser.HEADER_SIZE, out, DnsParser.HEADER_SIZE, qLen)
        }
        return out
    }

    fun put(query: DnsQuery, response: ByteArray) {
        val rcode = DnsParser.rcode(response)
        if (rcode != DnsRcode.NOERROR && rcode != DnsRcode.NXDOMAIN) return
        if (DnsParser.isTruncated(response)) return
        val ttl = (DnsParser.minTtl(response) ?: negativeTtlSeconds).coerceAtMost(maxTtlSeconds)
        if (ttl <= 0) return
        val expires = nanoClock() + ttl * 1_000_000_000L
        synchronized(map) { map[key(query)] = Entry(response.copyOf(), expires) }
    }

    fun clear() = synchronized(map) { map.clear() }

    val size: Int get() = synchronized(map) { map.size }
}
