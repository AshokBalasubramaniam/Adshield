package com.adshield.engine

import com.adshield.domain.model.AllowReason
import com.adshield.domain.model.BlockCategory
import com.adshield.domain.model.FilterDecision

/** Immutable rule snapshot; swapped atomically so the DNS hot path never takes a lock for rules. */
class RuleSnapshot(
    val categorySets: Map<BlockCategory, DomainSet> = emptyMap(),
    val userBlock: DomainSet = DomainSet.EMPTY,
    val userAllowGlobal: DomainSet = DomainSet.EMPTY,
    val userAllowByApp: Map<String, DomainSet> = emptyMap(),
    val loadedAtMillis: Long = 0L,
    val protectStreamingFirstParty: Boolean = true,
) {
    val listDomainCount: Int = categorySets.values.sumOf { it.size }

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
        if (snap.userAllowGlobal.contains(domain)) return FilterDecision.Allow(AllowReason.USER_GLOBAL)
        snap.userBlock.findMatch(domain)?.let { return FilterDecision.Block(BlockCategory.CUSTOM, it) }
        if (EssentialDomains.isEssential(domain, snap.protectStreamingFirstParty)) return FilterDecision.Allow(AllowReason.ESSENTIAL)
        for (category in LIST_ORDER) {
            val rule = snap.categorySets[category]?.findMatch(domain)
            if (rule != null) return FilterDecision.Block(category, rule)
        }
        return FilterDecision.Allow(AllowReason.NO_MATCH)
    }

    private companion object {
        val LIST_ORDER = listOf(BlockCategory.MALWARE, BlockCategory.PHISHING, BlockCategory.TRACKER, BlockCategory.ADS)
    }
}
