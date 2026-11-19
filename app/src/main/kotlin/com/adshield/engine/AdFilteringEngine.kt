package com.adshield.engine

import com.adshield.domain.model.AllowReason
import com.adshield.domain.model.BlockCategory
import com.adshield.domain.model.FilterDecision

/** One downloaded or bundled filter list, kept separate so a decision can name the list that caused it. */
class ListSet(val id: String, val name: String, val category: BlockCategory, val domains: DomainSet)

/** Immutable rule snapshot; swapped atomically so the DNS hot path never takes a lock for rules. */
class RuleSnapshot(
    val categorySets: Map<BlockCategory, DomainSet> = emptyMap(),
    val userBlock: DomainSet = DomainSet.EMPTY,
    val userAllowGlobal: DomainSet = DomainSet.EMPTY,
    val userAllowByApp: Map<String, DomainSet> = emptyMap(),
    val loadedAtMillis: Long = 0L,
    val protectStreamingFirstParty: Boolean = true,
    val protectYoutubeFirstParty: Boolean = true,
    val listSets: List<ListSet> = emptyList(),
) {
    val listDomainCount: Int = categorySets.values.sumOf { it.size } + listSets.sumOf { it.domains.size }
    private val categories = BlockCategory.entries
    internal val listSetsByCategory: Array<Array<ListSet>> = Array(categories.size) { i -> listSets.filter { it.category == categories[i] }.toTypedArray() }
    internal val categorySetArray: Array<DomainSet?> = Array(categories.size) { i -> categorySets[categories[i]] }

    companion object {
        val EMPTY = RuleSnapshot()
    }
}

/**
 * Decides whether a DNS name is blocked.
 *
 * Precedence (first match wins):
 *  1. user allow rule for the querying app
 *  2. user allow rule (global)
 *  3. user block rule
 *  4. built-in essential domains (never blocked by public lists; see [EssentialDomains])
 *  5. malware, phishing, tracker, ad lists (in that order, so the most severe label wins)
 *  6. otherwise allowed
 *
 * Thread-safe. Decisions are cached in a bounded LRU that is cleared whenever rules change.
 */
class AdFilteringEngine(private val cacheSize: Int = 4096) {
    @Volatile
    private var snapshot: RuleSnapshot = RuleSnapshot.EMPTY

    private val decisionCache = object : LinkedHashMap<String, FilterDecision>(512, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, FilterDecision>?): Boolean = size > cacheSize
    }

    val isLoaded: Boolean get() = snapshot.loadedAtMillis != 0L
    val domainCount: Int get() = snapshot.listDomainCount

    fun update(newSnapshot: RuleSnapshot) {
        synchronized(decisionCache) {
            snapshot = newSnapshot
            decisionCache.clear()
        }
    }

    /** @param domain already normalised (lower-case, no trailing dot). */
    fun evaluate(domain: String, packageName: String? = null): FilterDecision {
        val snap = snapshot
        if (packageName != null) {
            val appAllow = snap.userAllowByApp[packageName]
            if (appAllow != null && appAllow.contains(domain)) return FilterDecision.Allow(AllowReason.USER_APP)
        }
        synchronized(decisionCache) { decisionCache[domain] }?.let { return it }
        val decision = compute(snap, domain)
        synchronized(decisionCache) {
            // Only cache if rules were not swapped while we were computing.
            if (snapshot === snap) decisionCache[domain] = decision
        }
        return decision
    }

    private fun compute(snap: RuleSnapshot, domain: String): FilterDecision {
        // One suffix walk shared by every set below (the substrings are the main allocation on this path).
        val suffixes = DomainSet.Suffixes.of(domain)
        if (snap.userAllowGlobal.findMatch(suffixes) != null) return FilterDecision.Allow(AllowReason.USER_GLOBAL)
        snap.userBlock.findMatch(suffixes)?.let { return FilterDecision.Block(BlockCategory.CUSTOM, it) }
        if (EssentialDomains.isEssential(domain, suffixes, snap.protectStreamingFirstParty, snap.protectYoutubeFirstParty)) {
            return FilterDecision.Allow(AllowReason.ESSENTIAL)
        }
        for (category in LIST_ORDER) {
            val i = category.ordinal
            val rule = snap.categorySetArray[i]?.findMatch(suffixes)
            if (rule != null) return FilterDecision.Block(category, rule)
            val lists = snap.listSetsByCategory[i]
            for (j in lists.indices) {
                val ls = lists[j]
                val r = ls.domains.findMatch(suffixes)
                if (r != null) return FilterDecision.Block(category, r, ls.id)
            }
        }
        return FilterDecision.Allow(AllowReason.NO_MATCH)
    }

    private companion object {
        val LIST_ORDER = arrayOf(BlockCategory.MALWARE, BlockCategory.PHISHING, BlockCategory.TRACKER, BlockCategory.ADS)
    }
}
