package com.adshield.engine

/**
 * Immutable set of domains with suffix semantics: a rule "example.com" matches "example.com" and every
 * subdomain ("a.b.example.com"). Lookup is O(number of labels) hash probes, independent of list size.
 */
class DomainSet private constructor(private val domains: HashSet<String>) {
    val size: Int get() = domains.size

    /**
     * The domain and each of its parent suffixes, computed once so several sets can be probed without re-allocating
     * the substrings for every set ("a.b.c.com" -> a.b.c.com, b.c.com, c.com, com).
     */
    class Suffixes private constructor(@JvmField val parts: Array<String>) {
        companion object {
            fun of(domain: String): Suffixes {
                var count = 1
                for (c in domain) if (c == '.') count++
                val out = arrayOfNulls<String>(count)
                var cur = domain
                var i = 0
                while (true) {
                    out[i++] = cur
                    val dot = cur.indexOf('.')
                    if (dot < 0) break
                    cur = cur.substring(dot + 1)
                }
                @Suppress("UNCHECKED_CAST")
                return Suffixes(out as Array<String>)
            }
        }
    }

    /** Same as [findMatch] but reuses precomputed [suffixes] (no allocation). */
    fun findMatch(suffixes: Suffixes): String? {
        if (domains.isEmpty()) return null
        val parts = suffixes.parts
        for (i in parts.indices) if (parts[i] in domains) return parts[i]
        return null
    }

    /** Returns the matching rule (the domain or its closest matching parent), or null. */
    fun findMatch(domain: String): String? {
        if (domains.isEmpty()) return null
        var cur = domain
        while (true) {
            if (cur in domains) return cur
            val dot = cur.indexOf('.')
            if (dot < 0) return null
            cur = cur.substring(dot + 1)
        }
    }

    fun contains(domain: String): Boolean = findMatch(domain) != null

    class Builder(expected: Int = 16) {
        private val set = HashSet<String>(maxOf(16, (expected / 0.75f).toInt() + 1))
        val size: Int get() = set.size
        fun add(domain: String): Builder {
            set.add(domain)
            return this
        }
        fun build(): DomainSet = DomainSet(set)
    }

    companion object {
        val EMPTY = DomainSet(HashSet())
        fun of(vararg domains: String): DomainSet = Builder(domains.size).also { b -> domains.forEach { b.add(it) } }.build()
    }
}
