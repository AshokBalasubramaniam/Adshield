package com.adshield.dns

import com.adshield.domain.model.BlockMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Random

class DnsMessageTest {
    @Test fun parsesAQuery() {
        val q = DnsParser.parseQuery(DnsTestUtil.query("Ads.Example.COM", DnsType.A))!!
        assertEquals("ads.example.com", q.name); assertEquals(DnsType.A, q.type); assertEquals(0x1234, q.id)
    }
    @Test fun parsesAaaaAndHttps() {
        assertEquals(DnsType.AAAA, DnsParser.parseQuery(DnsTestUtil.query("a.com", DnsType.AAAA))!!.type)
        assertEquals(DnsType.HTTPS, DnsParser.parseQuery(DnsTestUtil.query("a.com", DnsType.HTTPS))!!.type)
    }
    @Test fun rejectsResponsesAndMultiQuestion() {
        val resp = DnsTestUtil.aResponse(DnsTestUtil.query("a.com", 1))
        assertNull(DnsParser.parseQuery(resp))
        val multi = DnsTestUtil.query("a.com", 1).also { it[5] = 2 }
        assertNull(DnsParser.parseQuery(multi))
    }
    @Test fun rejectsCompressionPointerInQuestion() {
        val q = DnsTestUtil.query("a.com", 1); q[12] = 0xC0.toByte()
        assertNull(DnsParser.parseQuery(q))
    }
    @Test fun rejectsTruncatedAtEveryLength() {
        val q = DnsTestUtil.query("some.long.example.com", 1)
        for (n in 0 until q.size - 4) assertNull("len $n", DnsParser.parseQuery(q.copyOf(n)))
    }
    @Test fun neverThrowsOnRandomBytes() {
        val rnd = Random(42)
        repeat(20_000) {
            val b = ByteArray(rnd.nextInt(200)); rnd.nextBytes(b)
            DnsParser.parseQuery(b); DnsParser.minTtl(b); DnsParser.clientUdpLimit(b); DnsResponseBuilder.formErr(b)
        }
    }
    @Test fun neverThrowsOnMutatedValidQueries() {
        val rnd = Random(1); val base = DnsTestUtil.query("www.example.com", 1, edns = 1232)
        repeat(20_000) { val b = base.copyOf(); b[rnd.nextInt(b.size)] = rnd.nextInt().toByte(); DnsParser.parseQuery(b); DnsParser.clientUdpLimit(b) }
    }
    @Test fun blockedAIsNullAddress() {
        val q = DnsParser.parseQuery(DnsTestUtil.query("ads.example.com", DnsType.A))!!
        val r = DnsResponseBuilder.blocked(q, BlockMode.NULL_IP)
        assertEquals(0x1234, DnsParser.u16(r, 0)); assertEquals(DnsRcode.NOERROR, DnsParser.rcode(r))
        assertEquals(1, DnsParser.u16(r, 6)); assertTrue(r.takeLast(4).all { it == 0.toByte() })
        assertEquals(60L, DnsParser.minTtl(r))
    }
    @Test fun blockedAaaaIsNullV6() {
        val q = DnsParser.parseQuery(DnsTestUtil.query("ads.example.com", DnsType.AAAA))!!
        val r = DnsResponseBuilder.blocked(q, BlockMode.NULL_IP)
        assertEquals(1, DnsParser.u16(r, 6)); assertTrue(r.takeLast(16).all { it == 0.toByte() })
    }
    @Test fun blockedOtherTypesAreNodata() {
        val q = DnsParser.parseQuery(DnsTestUtil.query("ads.example.com", DnsType.HTTPS))!!
        val r = DnsResponseBuilder.blocked(q, BlockMode.NULL_IP)
        assertEquals(0, DnsParser.u16(r, 6)); assertEquals(DnsRcode.NOERROR, DnsParser.rcode(r))
    }
    @Test fun nxdomainMode() {
        val q = DnsParser.parseQuery(DnsTestUtil.query("ads.example.com", DnsType.A))!!
        assertEquals(DnsRcode.NXDOMAIN, DnsParser.rcode(DnsResponseBuilder.blocked(q, BlockMode.NXDOMAIN)))
    }
    @Test fun blockedResponseEchoesRdFlagAndQuestion() {
        val raw = DnsTestUtil.query("ads.example.com", 1, rd = false)
        val q = DnsParser.parseQuery(raw)!!
        val r = DnsResponseBuilder.blocked(q, BlockMode.NULL_IP)
        assertEquals(0, r[2].toInt() and 1)
        assertTrue(raw.copyOfRange(12, q.questionEnd).contentEquals(r.copyOfRange(12, q.questionEnd)))
    }
    @Test fun minTtlReadsAnswers() = assertEquals(77L, DnsParser.minTtl(DnsTestUtil.aResponse(DnsTestUtil.query("a.com", 1), ttl = 77)))
    @Test fun minTtlRejectsTruncatedResponse() {
        val r = DnsTestUtil.aResponse(DnsTestUtil.query("a.com", 1))
        for (n in 12 until r.size) assertNull("len $n", DnsParser.minTtl(r.copyOf(n)))
    }
    @Test fun clientUdpLimit() {
        assertEquals(512, DnsParser.clientUdpLimit(DnsTestUtil.query("a.com", 1)))
        assertEquals(1232, DnsParser.clientUdpLimit(DnsTestUtil.query("a.com", 1, edns = 1232)))
    }
    @Test fun formErrKeepsId() { val f = DnsResponseBuilder.formErr(byteArrayOf(9, 8, 1))!!; assertEquals(9, f[0].toInt()); assertEquals(DnsRcode.FORMERR, DnsParser.rcode(f)); assertNotNull(f) }
}

class DnsCacheTest {
    @Test fun hitReturnsResponseWithNewId() {
        var now = 0L; val c = DnsCache(nanoClock = { now })
        val q1 = DnsParser.parseQuery(DnsTestUtil.query("a.com", 1, id = 1))!!
        c.put(q1, DnsTestUtil.aResponse(q1.raw, ttl = 100))
        val q2 = DnsParser.parseQuery(DnsTestUtil.query("A.com", 1, id = 0xBEEF))!!
        assertEquals(0xBEEF, DnsParser.u16(c.get(q2)!!, 0))
    }
    @Test fun expiresAfterTtl() {
        var now = 0L; val c = DnsCache(nanoClock = { now })
        val q = DnsParser.parseQuery(DnsTestUtil.query("a.com", 1))!!
        c.put(q, DnsTestUtil.aResponse(q.raw, ttl = 10))
        now = 9_000_000_000L; assertNotNull(c.get(q))
        now = 10_000_001_000L; assertNull(c.get(q))
    }
    @Test fun clampsLongTtl() {
        var now = 0L; val c = DnsCache(maxTtlSeconds = 300, nanoClock = { now })
        val q = DnsParser.parseQuery(DnsTestUtil.query("a.com", 1))!!
        c.put(q, DnsTestUtil.aResponse(q.raw, ttl = 86400))
        now = 301_000_000_000L; assertNull(c.get(q))
    }
    @Test fun doesNotCacheFailuresOrZeroTtl() {
        val c = DnsCache(); val q = DnsParser.parseQuery(DnsTestUtil.query("a.com", 1))!!
        c.put(q, DnsTestUtil.aResponse(q.raw, rcode = DnsRcode.SERVFAIL)); assertNull(c.get(q))
        c.put(q, DnsTestUtil.aResponse(q.raw, ttl = 0)); assertNull(c.get(q))
    }
    @Test fun cachesNxdomainBriefly() {
        var now = 0L; val c = DnsCache(nanoClock = { now }); val q = DnsParser.parseQuery(DnsTestUtil.query("nx.com", 1))!!
        c.put(q, DnsTestUtil.aResponse(q.raw, rcode = DnsRcode.NXDOMAIN)); assertNotNull(c.get(q))
        now = 31_000_000_000L; assertNull(c.get(q))
    }
    @Test fun lruEvicts() {
        val c = DnsCache(maxEntries = 2)
        for (n in listOf("a.com", "b.com", "c.com")) { val q = DnsParser.parseQuery(DnsTestUtil.query(n, 1))!!; c.put(q, DnsTestUtil.aResponse(q.raw)) }
        assertEquals(2, c.size)
    }
    @Test fun typesAreCachedSeparately() {
        val c = DnsCache(); val a = DnsParser.parseQuery(DnsTestUtil.query("a.com", 1))!!
        c.put(a, DnsTestUtil.aResponse(a.raw)); assertNull(c.get(DnsParser.parseQuery(DnsTestUtil.query("a.com", 28))!!))
    }
}

class DnsTruncateTest {
    @Test fun truncateKeepsQuestionSetsTcAndClearsCounts() {
        val q = DnsTestUtil.query("a.example.com", 1)
        val r = DnsTestUtil.aResponse(q)
        val t = DnsResponseBuilder.truncate(r)!!
        assertTrue(DnsParser.isTruncated(t)); assertEquals(0, DnsParser.u16(t, 6)); assertEquals(DnsParser.questionEndOf(r), t.size)
    }
    @Test fun truncateRejectsGarbage() { assertNull(DnsResponseBuilder.truncate(ByteArray(5))); assertNull(DnsResponseBuilder.truncate(ByteArray(40) { 0x3F })) }
}
