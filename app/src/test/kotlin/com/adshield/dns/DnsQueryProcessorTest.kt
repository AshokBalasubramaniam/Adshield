package com.adshield.dns

import com.adshield.domain.model.AllowReason
import com.adshield.domain.model.BlockCategory
import com.adshield.domain.model.BlockMode
import com.adshield.domain.model.FilterDecision
import com.adshield.engine.AdFilteringEngine
import com.adshield.engine.DomainSet
import com.adshield.engine.RuleSnapshot
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pipeline integration test: real engine + real cache + real parser/builder, fake upstream. */
class DnsQueryProcessorTest {
    private class Fixture(upstreamImpl: DnsUpstream? = null, mode: BlockMode = BlockMode.NULL_IP) {
        val events = mutableListOf<DnsEvent>()
        var upstreamCalls = 0
        val engine = AdFilteringEngine().apply {
            update(RuleSnapshot(mapOf(BlockCategory.ADS to DomainSet.of("ads.example.com")), allowAll(), loaded = true))
        }
        val processor = DnsQueryProcessor(
            engine, DnsCache(),
            upstream = { upstreamImpl ?: DnsUpstream { q -> upstreamCalls++; DnsTestUtil.aResponse(q) } },
            blockMode = { mode }, sink = { events += it },
        )
        companion object {
            fun allowAll() = DomainSet.EMPTY
            @Suppress("UNUSED_PARAMETER")
            fun RuleSnapshot(sets: Map<BlockCategory, DomainSet>, userAllow: DomainSet, loaded: Boolean) =
                com.adshield.engine.RuleSnapshot(categorySets = sets, userAllowGlobal = userAllow, loadedAtMillis = if (loaded) 1 else 0)
        }
    }

    @Test fun blockedNeverReachesUpstream() = runBlocking {
        val f = Fixture()
        val r = f.processor.process(DnsTestUtil.query("sub.ads.example.com", DnsType.A), "com.app")!!
        assertEquals(0, f.upstreamCalls)
        assertTrue(r.takeLast(4).all { it == 0.toByte() })
        assertTrue(f.events.single().decision is FilterDecision.Block)
        assertEquals("com.app", f.events.single().packageName)
    }
    @Test fun allowedIsForwardedThenServedFromCache() = runBlocking {
        val f = Fixture()
        f.processor.process(DnsTestUtil.query("example.com", DnsType.A, id = 1), null)
        val second = f.processor.process(DnsTestUtil.query("example.com", DnsType.A, id = 2), null)!!
        assertEquals(1, f.upstreamCalls); assertEquals(2, DnsParser.u16(second, 0))
        assertEquals(listOf(false, true), f.events.map { it.fromCache })
        assertEquals(FilterDecision.Allow(AllowReason.NO_MATCH), f.events[0].decision)
    }
    @Test fun upstreamFailureYieldsServfailAndIsNotCached() = runBlocking {
        var calls = 0
        val f = Fixture(DnsUpstream { calls++; null })
        val r = f.processor.process(DnsTestUtil.query("example.com", DnsType.A), null)!!
        assertEquals(DnsRcode.SERVFAIL, DnsParser.rcode(r)); assertTrue(f.events.single().failed)
        f.processor.process(DnsTestUtil.query("example.com", DnsType.A), null); assertEquals(2, calls)
    }
    @Test fun upstreamTimeoutYieldsServfail() = runBlocking {
        val events = mutableListOf<DnsEvent>()
        val p = DnsQueryProcessor(AdFilteringEngine(), DnsCache(), { DnsUpstream { delay(10_000); null } }, { BlockMode.NULL_IP }, { events += it }, upstreamTimeoutMs = 50)
        assertEquals(DnsRcode.SERVFAIL, DnsParser.rcode(p.process(DnsTestUtil.query("example.com", 1), null)!!))
    }
    @Test fun noUpstreamAvailableYieldsServfail() = runBlocking {
        val p = DnsQueryProcessor(AdFilteringEngine(), DnsCache(), { null }, { BlockMode.NULL_IP }, { })
        assertEquals(DnsRcode.SERVFAIL, DnsParser.rcode(p.process(DnsTestUtil.query("example.com", 1), null)!!))
    }
    @Test fun malformedGetsFormErrOrDrop() = runBlocking {
        val f = Fixture()
        assertEquals(DnsRcode.FORMERR, DnsParser.rcode(f.processor.process(ByteArray(5) { 1 }, null)!!))
        assertNull(f.processor.process(ByteArray(1), null)); assertEquals(0, f.upstreamCalls)
    }
    @Test fun nonStandardOpcodeIsNotImplemented() = runBlocking {
        val q = DnsTestUtil.query("example.com", 1).also { it[2] = (it[2].toInt() or (4 shl 3)).toByte() }
        assertEquals(DnsRcode.NOTIMP, DnsParser.rcode(Fixture().processor.process(q, null)!!))
    }
    @Test fun nxdomainModeIsHonoured() = runBlocking {
        val r = Fixture(mode = BlockMode.NXDOMAIN).processor.process(DnsTestUtil.query("ads.example.com", 1), null)!!
        assertEquals(DnsRcode.NXDOMAIN, DnsParser.rcode(r)); assertNotNull(r)
    }
}
