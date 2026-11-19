package com.adshield.youtube

import com.adshield.dns.DnsEvent
import com.adshield.domain.model.AllowReason
import com.adshield.domain.model.BlockCategory
import com.adshield.domain.model.FilterDecision
import com.adshield.engine.AdFilteringEngine
import com.adshield.engine.DomainSet
import com.adshield.engine.ListSet
import com.adshield.engine.RuleSnapshot
import com.adshield.ui.screens.playbackCompatibility
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class YoutubeClassifierTest {
    private fun c(d: String) = YoutubeClassifier.classify(d)

    @Test fun mapsKnownYoutubeInfrastructure() {
        assertEquals(YoutubeClass.VIDEO_CDN, c("rr1---sn-4g5e6nsz.googlevideo.com"))
        assertEquals(YoutubeClass.THUMBNAILS, c("i.ytimg.com"))
        assertEquals(YoutubeClass.THUMBNAILS, c("yt3.ggpht.com"))
        assertEquals(YoutubeClass.FIRST_PARTY, c("www.youtube.com"))
        assertEquals(YoutubeClass.FIRST_PARTY, c("youtubei.googleapis.com")) // more specific than googleapis.com
        assertEquals(YoutubeClass.AUTH, c("accounts.google.com"))
        assertEquals(YoutubeClass.AD_SERVING, c("googleads.g.doubleclick.net"))
        assertEquals(YoutubeClass.AD_SERVING, c("pagead2.googlesyndication.com"))
        assertEquals(YoutubeClass.ANALYTICS, c("www.google-analytics.com"))
        assertEquals(YoutubeClass.OTHER_GOOGLE, c("clients4.google.com"))
    }

    @Test fun matchesWholeLabelsNeverKeywordsOrLookalikes() {
        listOf("notgooglevideo.com", "googlevideo.com.evil.example", "youtube.com.phish.example", "my-youtube.example",
            "ads.example.org", "adserver.legit.com", "doubleclick.example").forEach { assertEquals(it, YoutubeClass.OTHER, c(it)) }
    }

    @Test fun relatedRespectsAttributionButNotOtherGoogle() {
        assertTrue(YoutubeClassifier.isYoutubeRelated(YoutubeClass.VIDEO_CDN, null))
        assertFalse(YoutubeClassifier.isYoutubeRelated(YoutubeClass.OTHER, null))
        assertFalse(YoutubeClassifier.isYoutubeRelated(YoutubeClass.OTHER_GOOGLE, null))
        assertTrue("any lookup by the YouTube app is recorded", YoutubeClassifier.isYoutubeRelated(YoutubeClass.OTHER, YoutubeClassifier.APP_PACKAGE))
        assertFalse(YoutubeClassifier.isYoutubeRelated(YoutubeClass.OTHER, "com.example.other"))
    }

    @Test fun sameOriginRiskIsFlaggedOnlyWhereItIsReal() {
        assertTrue(YoutubeClass.VIDEO_CDN.mayCarrySameOriginAds && YoutubeClass.FIRST_PARTY.mayCarrySameOriginAds)
        assertFalse(YoutubeClass.AD_SERVING.mayCarrySameOriginAds || YoutubeClass.THUMBNAILS.mayCarrySameOriginAds)
        assertTrue(YoutubeClass.VIDEO_CDN.playbackCritical && !YoutubeClass.AD_SERVING.playbackCritical)
    }
}

class YoutubeDiagnosticsTest {
    private fun block(cat: BlockCategory = BlockCategory.ADS) = FilterDecision.Block(cat, "doubleclick.net", "adaway")
    private fun ev(domain: String, d: FilterDecision?, pkg: String? = null, failed: Boolean = false, cache: Boolean = false) =
        DnsEvent(domain, pkg, d, cache, failed, qtype = 1, micros = 42)

    @Test fun countersAreRealAndSplitByClassAndVerdict() {
        val d = YoutubeDiagnostics()
        d.onQuery(ev("googleads.g.doubleclick.net", block()))
        d.onQuery(ev("googleads.g.doubleclick.net", block()))
        d.onQuery(ev("www.google-analytics.com", block(BlockCategory.TRACKER)))
        d.onQuery(ev("rr1.googlevideo.com", FilterDecision.Allow(AllowReason.ESSENTIAL)))
        d.onQuery(ev("www.youtube.com", FilterDecision.Allow(AllowReason.NO_MATCH)))
        d.onQuery(ev("example.com", FilterDecision.Allow(AllowReason.NO_MATCH))) // unrelated: not counted
        val s = d.snapshot()
        assertEquals(5, s.totalRelated); assertEquals(2, s.adServingBlocked); assertEquals(1, s.trackersBlocked); assertEquals(2, s.allowedYoutube)
        assertEquals(0, s.playbackCriticalProblems)
    }

    @Test fun blockedOrFailedPlaybackCriticalLookupsAreCountedAsProblems() {
        val d = YoutubeDiagnostics()
        d.onQuery(ev("rr1.googlevideo.com", block()))
        d.onQuery(ev("i.ytimg.com", FilterDecision.Allow(AllowReason.NO_MATCH), failed = true))
        d.onQuery(ev("googleads.g.doubleclick.net", block())) // ad domain blocked is NOT a playback problem
        assertEquals(2, d.snapshot().playbackCriticalProblems)
    }

    @Test fun logIsOffByDefaultAndCountersStillWork() {
        val d = YoutubeDiagnostics()
        d.onQuery(ev("rr1.googlevideo.com", FilterDecision.Allow(AllowReason.ESSENTIAL)))
        assertTrue(d.entries().isEmpty()); assertEquals(1, d.snapshot().totalRelated)
    }

    @Test fun recordedEntriesCarryTheExactRuleAndAreNewestFirst() {
        val d = YoutubeDiagnostics().apply { recording = true }
        d.onQuery(ev("first.googlevideo.com", FilterDecision.Allow(AllowReason.ESSENTIAL)))
        d.onQuery(DnsEvent("metrics.youtube.com", null, FilterDecision.Block(BlockCategory.TRACKER, "adnet.example", "urlhaus", "c.adnet.example"), false, false, 1, listOf("c.adnet.example"), 7))
        val e = d.entries()
        assertEquals("metrics.youtube.com", e[0].domain); assertEquals("adnet.example", e[0].matchedRule); assertEquals("urlhaus", e[0].sourceId)
        assertEquals("c.adnet.example", e[0].viaCname); assertEquals(Verdict.BLOCKED_TRACKER, e[0].verdict)
        assertEquals(Verdict.ALLOWED_ESSENTIAL, e[1].verdict)
    }

    @Test fun logIsBounded() {
        val d = YoutubeDiagnostics().apply { recording = true }
        repeat(3000) { d.onQuery(ev("r$it.googlevideo.com", FilterDecision.Allow(AllowReason.ESSENTIAL))) }
        assertEquals(1500, d.entries().size); assertEquals(3000, d.snapshot().totalRelated)
        assertEquals("r2999.googlevideo.com", d.entries().first().domain)
    }

    @Test fun lookupsByTheYoutubeAppAreRecordedEvenForUnrelatedNames() {
        val d = YoutubeDiagnostics().apply { recording = true }
        d.onQuery(ev("some-cdn.example", FilterDecision.Allow(AllowReason.NO_MATCH), pkg = YoutubeClassifier.APP_PACKAGE))
        d.onQuery(ev("some-cdn.example", FilterDecision.Allow(AllowReason.NO_MATCH), pkg = "com.other"))
        assertEquals(1, d.entries().size); assertEquals(1, d.snapshot().attributedToYoutube)
    }

    @Test fun bypassSignalsAreCountedPerPort() {
        val d = YoutubeDiagnostics()
        val addr = byteArrayOf(8, 8, 8, 8)
        d.onHardcodedResolverQuery(addr); d.onHardcodedResolverQuery(addr)
        d.onRefusedTcp(addr, 853); d.onRefusedTcp(addr, 853); d.onRefusedTcp(addr, 443)
        d.onDroppedUdp(addr, 443)
        val b = d.snapshot().bypass
        assertEquals(2, b.hardcodedResolverQueries); assertEquals(mapOf(853 to 2L, 443 to 1L), b.refusedTcpByPort)
        assertEquals(4, b.encryptedDnsAttempts)
    }

    @Test fun clearForgetsEverythingAboutTheSession() {
        val d = YoutubeDiagnostics().apply { recording = true }
        d.onQuery(ev("rr1.googlevideo.com", block())); d.onRefusedTcp(byteArrayOf(1, 1, 1, 1), 853)
        d.clear()
        val s = d.snapshot()
        assertEquals(0, s.totalRelated); assertTrue(d.entries().isEmpty()); assertEquals(0, s.bypass.encryptedDnsAttempts); assertNull(s.attribution)
    }

    @Test fun failedLookupsAreNeverReportedAsBlocked() {
        val d = YoutubeDiagnostics()
        d.onQuery(ev("googleads.g.doubleclick.net", block(), failed = true))
        assertEquals(0, d.snapshot().adServingBlocked); assertEquals(1, d.snapshot().count(YoutubeClass.AD_SERVING, Verdict.FAILED))
    }

    @Test fun playbackCompatibilityNeverClaimsAdBlocking() {
        val off = playbackCompatibility(YoutubeDiagnostics().snapshot(), running = false).first
        assertTrue(off.contains("Not measured"))
        val d = YoutubeDiagnostics()
        assertTrue(playbackCompatibility(d.snapshot(), true).first.contains("No YouTube-related lookups"))
        d.onQuery(ev("rr1.googlevideo.com", FilterDecision.Allow(AllowReason.ESSENTIAL)))
        assertTrue(playbackCompatibility(d.snapshot(), true).first.contains("No playback-critical lookup was blocked"))
        d.onQuery(ev("i.ytimg.com", block()))
        assertTrue(playbackCompatibility(d.snapshot(), true).first.startsWith("At risk"))
        listOf(off, playbackCompatibility(d.snapshot(), true).first).forEach { assertFalse(it.lowercase().contains("ads blocked")) }
    }
}

class KeywordSafetyTest {
    @Test fun domainsAreNeverBlockedForMerelyLookingAdLike() {
        val e = AdFilteringEngine().apply {
            update(RuleSnapshot(listSets = listOf(ListSet("l", "L", BlockCategory.ADS, DomainSet.of("doubleclick.net"))), loadedAtMillis = 1))
        }
        listOf("ads.example.com", "adserver.legit.org", "banner-ads.news.example", "tracking.shop.example", "doubleclick.net.example", "my-doubleclick.net")
            .forEach { assertEquals(it, FilterDecision.Allow(AllowReason.NO_MATCH), e.evaluate(it)) }
        assertTrue(e.evaluate("x.doubleclick.net") is FilterDecision.Block)
    }
}
