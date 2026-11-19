package com.adshield.integration

import com.adshield.dns.DnsCache
import com.adshield.dns.DnsEvent
import com.adshield.dns.DnsParser
import com.adshield.dns.DnsQueryProcessor
import com.adshield.dns.DnsRcode
import com.adshield.dns.DnsTestUtil
import com.adshield.dns.DnsType
import com.adshield.dns.DnsUpstream
import com.adshield.domain.model.BlockCategory
import com.adshield.domain.model.BlockMode
import com.adshield.domain.model.FilterDecision
import com.adshield.engine.AdFilteringEngine
import com.adshield.engine.DomainSet
import com.adshield.engine.RuleParser
import com.adshield.engine.RuleSnapshot
import com.adshield.vpn.packet.IpPacketBuilder
import com.adshield.vpn.packet.IpPacketParser
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Whole path without Android: IP packet from the "tunnel" → DNS processing with real list parsing, real
 * engine and cache → IP reply packet. Only the upstream resolver is faked.
 */
class EndToEndFilteringTest {
    private val adsHosts = """
        # ads
        127.0.0.1 localhost
        0.0.0.0 ads.tracker-example.com
        0.0.0.0 videoads.hotstar.com
        0.0.0.0 rr1.googlevideo.com
        ||banner.adnet.example^
    """.trimIndent()
    private val malwareList = "evil-downloads.example.org\n1.2.3.4\n"

    private val upstreamCalls = mutableListOf<String>()
    private val events = mutableListOf<DnsEvent>()

    private fun build(protectStreaming: Boolean = true): DnsQueryProcessor {
        fun setOf(text: String) = DomainSet.Builder().also { b -> RuleParser.parse(text) { b.add(it) } }.build()
        val engine = AdFilteringEngine().apply {
            update(RuleSnapshot(
                categorySets = mapOf(BlockCategory.ADS to setOf(adsHosts), BlockCategory.MALWARE to setOf(malwareList)),
                loadedAtMillis = 1, protectStreamingFirstParty = protectStreaming,
            ))
        }
        return DnsQueryProcessor(engine, DnsCache(), { DnsUpstream { q -> upstreamCalls += DnsParser.parseQuery(q)!!.name; DnsTestUtil.aResponse(q) } }, { BlockMode.NULL_IP }, { events += it })
    }

    private val client = byteArrayOf(10, 111, 222.toByte(), 1)
    private val dns = byteArrayOf(10, 111, 222.toByte(), 2)

    /** Sends [name] through the whole stack as a raw IPv4 UDP packet and returns the parsed DNS reply. */
    private fun ask(p: DnsQueryProcessor, name: String, type: Int = DnsType.A): ByteArray = runBlocking {
        val packet = IpPacketBuilder.buildUdp(client, dns, 51234, 53, DnsTestUtil.query(name, type))
        val udp = (IpPacketParser.parse(packet, packet.size) as IpPacketParser.Result.Udp).packet
        val reply = IpPacketBuilder.udpReply(udp, p.process(udp.payload, null)!!)
        (IpPacketParser.parse(reply, reply.size) as IpPacketParser.Result.Udp).packet.payload
    }

    private fun isNullAnswer(r: ByteArray) = DnsParser.u16(r, 6) == 1 && r.takeLast(4).all { it == 0.toByte() }

    @Test fun listedAdAndMalwareDomainsAreBlockedAndNeverResolved() {
        val p = build()
        assertTrue(isNullAnswer(ask(p, "ads.tracker-example.com")))
        assertTrue(isNullAnswer(ask(p, "cdn.ads.tracker-example.com")))
        assertTrue(isNullAnswer(ask(p, "banner.adnet.example")))
        assertTrue(isNullAnswer(ask(p, "evil-downloads.example.org")))
        assertTrue("blocked names must never be sent upstream", upstreamCalls.isEmpty())
        assertEquals(BlockCategory.MALWARE, ((events.last().decision) as FilterDecision.Block).category)
    }

    @Test fun normalDomainsAreResolvedAndLocalhostEntriesIgnored() {
        val p = build()
        val r = ask(p, "example.com")
        assertEquals(DnsRcode.NOERROR, DnsParser.rcode(r)); assertTrue(!isNullAnswer(r))
        assertEquals(listOf("example.com"), upstreamCalls)
        ask(p, "localhost.example.com"); assertEquals(2, upstreamCalls.size)
    }

    @Test fun videoDeliveryAndStreamingFirstPartyAreProtectedEvenIfListed() {
        val p = build()
        assertTrue(!isNullAnswer(ask(p, "rr1.googlevideo.com")))
        assertTrue(!isNullAnswer(ask(p, "videoads.hotstar.com")))
        assertEquals(listOf("rr1.googlevideo.com", "videoads.hotstar.com"), upstreamCalls)
    }

    @Test fun aggressiveStreamingModeBlocksListedHotstarHostButStillNotVideoCdn() {
        val p = build(protectStreaming = false)
        assertTrue(isNullAnswer(ask(p, "videoads.hotstar.com")))
        assertTrue(!isNullAnswer(ask(p, "rr1.googlevideo.com")))
    }

    @Test fun repeatedQueriesAreServedFromCache() {
        val p = build()
        repeat(5) { ask(p, "example.com") }
        assertEquals(1, upstreamCalls.size); assertEquals(4, events.count { it.fromCache })
    }

    @Test fun aaaaAndHttpsQueriesForBlockedNamesAreAnsweredLocally() {
        val p = build()
        val aaaa = ask(p, "ads.tracker-example.com", DnsType.AAAA)
        assertEquals(1, DnsParser.u16(aaaa, 6)); assertTrue(aaaa.takeLast(16).all { it == 0.toByte() })
        assertEquals(0, DnsParser.u16(ask(p, "ads.tracker-example.com", DnsType.HTTPS), 6))
        assertTrue(upstreamCalls.isEmpty())
    }
}
