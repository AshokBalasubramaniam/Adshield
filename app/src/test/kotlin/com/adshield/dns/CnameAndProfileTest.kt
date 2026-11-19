package com.adshield.dns

import com.adshield.domain.model.AllowReason
import com.adshield.domain.model.BlockCategory
import com.adshield.domain.model.BlockMode
import com.adshield.domain.model.FilterDecision
import com.adshield.engine.AdFilteringEngine
import com.adshield.engine.DomainSet
import com.adshield.engine.ListSet
import com.adshield.engine.RuleSnapshot
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Random

class CnameParserTest {
    private fun q(name: String) = DnsTestUtil.query(name, DnsType.A)

    @Test fun noCnameIsEmptyAndShared() {
        val r = DnsTestUtil.aResponse(q("a.example.com"))
        assertTrue(DnsParser.cnameTargets(r).isEmpty())
        assertTrue("no allocation in the common case", DnsParser.cnameTargets(r) === DnsParser.cnameTargets(r))
    }
    @Test fun singleAndChained() {
        assertEquals(listOf("t.adnet.example"), DnsParser.cnameTargets(DnsTestUtil.cnameResponse(q("a.example.com"), listOf("t.adnet.example"))))
        assertEquals(listOf("mid.cdn.example", "t.adnet.example"), DnsParser.cnameTargets(DnsTestUtil.cnameResponse(q("a.example.com"), listOf("MID.cdn.example", "t.adnet.example"))))
    }
    @Test fun pointerLoopIsRejectedNotFollowedForever() {
        val r = DnsTestUtil.cnameResponse(q("a.example.com"), listOf("t.adnet.example"))
        // Make the CNAME rdata a compression pointer to itself.
        val rdStart = DnsParser.questionEndOf(r)!! + 12
        r[rdStart] = 0xC0.toByte(); r[rdStart + 1] = rdStart.toByte()
        assertTrue(DnsParser.cnameTargets(r).isEmpty())
    }
    @Test fun invalidNamesAreSkipped() {
        val r = DnsTestUtil.cnameResponse(q("a.example.com"), listOf("bad name.example"))
        assertTrue(DnsParser.cnameTargets(r).isEmpty())
    }
    @Test fun truncatedAtEveryLengthNeverThrows() {
        val r = DnsTestUtil.cnameResponse(q("a.example.com"), listOf("mid.cdn.example", "t.adnet.example"))
        for (n in 0..r.size) DnsParser.cnameTargets(r.copyOf(n))
    }
    @Test fun randomAndMutatedNeverThrow() {
        val rnd = Random(5); val base = DnsTestUtil.cnameResponse(q("a.example.com"), listOf("mid.cdn.example", "t.adnet.example"))
        repeat(30_000) {
            val b = base.copyOf(); repeat(1 + rnd.nextInt(4)) { b[rnd.nextInt(b.size)] = rnd.nextInt().toByte() }
            DnsParser.cnameTargets(b)
            val junk = ByteArray(rnd.nextInt(120)); rnd.nextBytes(junk); DnsParser.cnameTargets(junk)
        }
    }
}

class CnameFilteringTest {
    private val events = mutableListOf<DnsEvent>()
    private var upstreamCalls = 0

    private fun engine(vararg listed: String, allow: Array<String> = emptyArray()) = AdFilteringEngine().apply { update(snapshot(*listed, allow = allow)) }
    private fun snapshot(vararg listed: String, allow: Array<String> = emptyArray()) = RuleSnapshot(
        listSets = listOf(ListSet("urlhaus", "Test list", BlockCategory.TRACKER, DomainSet.of(*listed))),
        userAllowGlobal = DomainSet.of(*allow), loadedAtMillis = 1,
    )
    private fun processor(e: AdFilteringEngine, cache: DnsCache = DnsCache(), chain: List<String>) = DnsQueryProcessor(
        e, cache, { DnsUpstream { qb -> upstreamCalls++; DnsTestUtil.cnameResponse(qb, chain) } }, { BlockMode.NULL_IP }, { events += it },
    )
    private fun ask(p: DnsQueryProcessor, name: String) = runBlocking { p.process(DnsTestUtil.query(name, DnsType.A), null)!! }
    private fun isNull(r: ByteArray) = DnsParser.u16(r, 6) == 1 && r.takeLast(4).all { it == 0.toByte() }

    @Test fun cnameCloakedTrackerIsBlockedAndAttributed() {
        val p = processor(engine("adnet.example"), chain = listOf("collect.adnet.example"))
        val r = ask(p, "metrics.news-site.example")
        assertTrue("answer must be neutralised", isNull(r))
        val d = events.last().decision as FilterDecision.Block
        assertEquals("collect.adnet.example", d.viaCname); assertEquals("adnet.example", d.matchedRule); assertEquals("urlhaus", d.sourceId)
        assertEquals(listOf("collect.adnet.example"), events.last().cnames)
    }
    @Test fun cleanCnameChainIsForwardedUntouched() {
        val p = processor(engine("adnet.example"), chain = listOf("edge.cdn.example"))
        assertTrue(!isNull(ask(p, "www.news-site.example")))
    }
    @Test fun essentialNamesAreNeverSecondGuessedThroughAliases() {
        val p = processor(engine("adnet.example"), chain = listOf("collect.adnet.example"))
        assertTrue(!isNull(ask(p, "rr1.googlevideo.com")))
        assertEquals(FilterDecision.Allow(AllowReason.ESSENTIAL), events.last().decision)
    }
    @Test fun userAllowedNamesAreNotBlockedViaCname() {
        val p = processor(engine("adnet.example", allow = arrayOf("metrics.news-site.example")), chain = listOf("collect.adnet.example"))
        assertTrue(!isNull(ask(p, "metrics.news-site.example")))
    }
    @Test fun cachedAnswersAreRecheckedWhenRulesChange() {
        val e = engine("unrelated.example"); val p = processor(e, chain = listOf("collect.adnet.example"))
        assertTrue(!isNull(ask(p, "metrics.news-site.example")))          // resolved + cached while target unlisted
        e.update(snapshot("adnet.example"))                               // list update arrives
        assertTrue("cache hit must honour the new rule", isNull(ask(p, "metrics.news-site.example")))
        assertEquals(1, upstreamCalls); assertTrue(events.last().fromCache)
    }
}

class ListAttributionAndProfileTest {
    private fun snap(aggressive: Boolean) = RuleSnapshot(
        listSets = listOf(
            ListSet("adaway", "AdAway", BlockCategory.ADS, DomainSet.of("ads.youtube.com", "doubleclick.net", "googlevideo.com")),
            ListSet("urlhaus", "URLhaus", BlockCategory.MALWARE, DomainSet.of("evil.example")),
        ),
        loadedAtMillis = 1, protectYoutubeFirstParty = !aggressive,
    )

    @Test fun decisionNamesTheListThatCausedIt() {
        val e = AdFilteringEngine().apply { update(snap(false)) }
        assertEquals(FilterDecision.Block(BlockCategory.ADS, "doubleclick.net", "adaway"), e.evaluate("googleads.g.doubleclick.net"))
        assertEquals(FilterDecision.Block(BlockCategory.MALWARE, "evil.example", "urlhaus"), e.evaluate("x.evil.example"))
    }
    @Test fun safeProfileProtectsYoutubeFirstPartyAggressiveDoesNot() {
        val safe = AdFilteringEngine().apply { update(snap(false)) }
        val aggr = AdFilteringEngine().apply { update(snap(true)) }
        assertEquals(FilterDecision.Allow(AllowReason.ESSENTIAL), safe.evaluate("ads.youtube.com"))
        assertTrue(aggr.evaluate("ads.youtube.com") is FilterDecision.Block)
    }
    @Test fun videoDeliveryStaysProtectedInEveryProfile() {
        val aggr = AdFilteringEngine().apply { update(snap(true)) }
        assertEquals(FilterDecision.Allow(AllowReason.ESSENTIAL), aggr.evaluate("rr3---sn-x.googlevideo.com"))
    }
    @Test fun domainCountCoversPerListSets() = assertEquals(4, snap(false).listDomainCount)
}
