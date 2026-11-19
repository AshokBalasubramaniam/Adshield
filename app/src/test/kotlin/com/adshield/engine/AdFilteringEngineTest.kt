package com.adshield.engine

import com.adshield.domain.model.AllowReason
import com.adshield.domain.model.BlockCategory
import com.adshield.domain.model.FilterDecision
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AdFilteringEngineTest {
    private fun engine(
        ads: Array<String> = emptyArray(), trackers: Array<String> = emptyArray(),
        malware: Array<String> = emptyArray(), userBlock: Array<String> = emptyArray(),
        allow: Array<String> = emptyArray(), appAllow: Map<String, Array<String>> = emptyMap(),
    ) = AdFilteringEngine().apply {
        update(RuleSnapshot(
            categorySets = mapOf(BlockCategory.ADS to DomainSet.of(*ads), BlockCategory.TRACKER to DomainSet.of(*trackers), BlockCategory.MALWARE to DomainSet.of(*malware)),
            userBlock = DomainSet.of(*userBlock), userAllowGlobal = DomainSet.of(*allow),
            userAllowByApp = appAllow.mapValues { DomainSet.of(*it.value) }, loadedAtMillis = 1,
        ))
    }

    @Test fun blocksListedAndSubdomains() {
        val e = engine(ads = arrayOf("ads.example.com"))
        assertEquals(FilterDecision.Block(BlockCategory.ADS, "ads.example.com"), e.evaluate("x.ads.example.com"))
        assertEquals(FilterDecision.Allow(AllowReason.NO_MATCH), e.evaluate("example.com"))
    }
    @Test fun mostSevereCategoryWins() {
        val e = engine(ads = arrayOf("bad.com"), malware = arrayOf("bad.com"), trackers = arrayOf("bad.com"))
        assertEquals(BlockCategory.MALWARE, (e.evaluate("bad.com") as FilterDecision.Block).category)
    }
    @Test fun userAllowBeatsEverything() {
        val e = engine(ads = arrayOf("ads.example.com"), userBlock = arrayOf("ads.example.com"), allow = arrayOf("ads.example.com"))
        assertEquals(FilterDecision.Allow(AllowReason.USER_GLOBAL), e.evaluate("ads.example.com"))
    }
    @Test fun appAllowOnlyAppliesToThatApp() {
        val e = engine(ads = arrayOf("ads.example.com"), appAllow = mapOf("com.a" to arrayOf("ads.example.com")))
        assertEquals(FilterDecision.Allow(AllowReason.USER_APP), e.evaluate("ads.example.com", "com.a"))
        assertTrue(e.evaluate("ads.example.com", "com.b") is FilterDecision.Block)
        assertTrue(e.evaluate("ads.example.com", null) is FilterDecision.Block)
    }
    @Test fun essentialDomainsAreNotBlockedByPublicLists() {
        val e = engine(ads = arrayOf("googlevideo.com", "r1.googlevideo.com", "youtube.com", "hotstar.com"))
        assertEquals(FilterDecision.Allow(AllowReason.ESSENTIAL), e.evaluate("rr1---sn-abc.googlevideo.com"))
        assertEquals(FilterDecision.Allow(AllowReason.ESSENTIAL), e.evaluate("www.youtube.com"))
        assertEquals(FilterDecision.Allow(AllowReason.ESSENTIAL), e.evaluate("api.hotstar.com"))
    }
    @Test fun aggressiveStreamingModeLiftsOnlyStreamingFirstPartyProtection() {
        val e = AdFilteringEngine().apply { update(RuleSnapshot(
            categorySets = mapOf(BlockCategory.ADS to DomainSet.of("videoads.hotstar.com", "googlevideo.com")),
            loadedAtMillis = 1, protectStreamingFirstParty = false)) }
        assertTrue(e.evaluate("videoads.hotstar.com") is FilterDecision.Block)
        assertEquals(FilterDecision.Allow(AllowReason.ESSENTIAL), e.evaluate("rr1.googlevideo.com")) // core stays protected
    }
    @Test fun userBlockOverridesEssential() {
        val e = engine(userBlock = arrayOf("ads.youtube.com"))
        assertEquals(BlockCategory.CUSTOM, (e.evaluate("ads.youtube.com") as FilterDecision.Block).category)
        assertEquals(FilterDecision.Allow(AllowReason.ESSENTIAL), e.evaluate("www.youtube.com"))
    }
    @Test fun exactEssentialDoesNotShieldAdSubdomainsOfGoogle() {
        val e = engine(ads = arrayOf("adservice.google.com"))
        assertTrue(e.evaluate("adservice.google.com") is FilterDecision.Block)
        assertEquals(FilterDecision.Allow(AllowReason.ESSENTIAL), e.evaluate("www.google.com"))
    }
    @Test fun updateInvalidatesDecisionCache() {
        val e = engine(ads = arrayOf("a.com"))
        assertTrue(e.evaluate("a.com") is FilterDecision.Block)
        e.update(RuleSnapshot(loadedAtMillis = 2))
        assertTrue(e.evaluate("a.com") is FilterDecision.Allow)
    }
}
