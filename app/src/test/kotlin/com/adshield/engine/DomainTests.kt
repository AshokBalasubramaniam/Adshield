package com.adshield.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DomainNormalizerTest {
    @Test fun lowercasesAndStripsTrailingDot() = assertEquals("ads.example.com", DomainNormalizer.normalize("ADS.Example.COM."))
    @Test fun rejectsEmptyAndDotOnly() {
        assertNull(DomainNormalizer.normalize(""))
        assertNull(DomainNormalizer.normalize("."))
        assertNull(DomainNormalizer.normalize("a..b"))
    }
    @Test fun rejectsBadCharsAndHyphenEdges() {
        assertNull(DomainNormalizer.normalize("exa mple.com"))
        assertNull(DomainNormalizer.normalize("-bad.com"))
        assertNull(DomainNormalizer.normalize("bad-.com"))
        assertNull(DomainNormalizer.normalize("ex/ample.com"))
        assertNull(DomainNormalizer.normalize("ünicode.com"))
    }
    @Test fun enforcesLengthLimits() {
        assertNull(DomainNormalizer.normalize("a".repeat(64) + ".com"))
        assertEquals("a".repeat(63) + ".com", DomainNormalizer.normalize("a".repeat(63) + ".com"))
        assertNull(DomainNormalizer.normalize(("a".repeat(50) + ".").repeat(6) + "com"))
    }
    @Test fun allowsUnderscoreAndPunycode() {
        assertEquals("_dmarc.example.com", DomainNormalizer.normalize("_dmarc.example.com"))
        assertEquals("xn--bcher-kva.example", DomainNormalizer.normalize("xn--bcher-kva.example"))
    }
    @Test fun ruleDomainNeedsDotAndIsNotAnIp() {
        assertNull(DomainNormalizer.normalizeRuleDomain("localhost"))
        assertNull(DomainNormalizer.normalizeRuleDomain("1.2.3.4"))
        assertEquals("a.io", DomainNormalizer.normalizeRuleDomain("a.io"))
    }
}

class DomainSetTest {
    @Test fun matchesExactAndSubdomains() {
        val s = DomainSet.of("ads.example.com", "tracker.net")
        assertEquals("ads.example.com", s.findMatch("ads.example.com"))
        assertEquals("ads.example.com", s.findMatch("x.y.ads.example.com"))
        assertEquals("tracker.net", s.findMatch("a.tracker.net"))
    }
    @Test fun doesNotMatchParentOrSiblingsOrSuffixLookalikes() {
        val s = DomainSet.of("ads.example.com")
        assertNull(s.findMatch("example.com"))
        assertNull(s.findMatch("other.example.com"))
        assertNull(s.findMatch("notads.example.com"))
        assertNull(s.findMatch("ads.example.com.evil.org"))
    }
    @Test fun emptySetNeverMatches() = assertFalse(DomainSet.EMPTY.contains("a.com"))
    @Test fun handlesLargeSetsQuickly() {
        val b = DomainSet.Builder(200_000)
        repeat(200_000) { b.add("host$it.example$it.com") }
        val s = b.build()
        val t = System.nanoTime()
        repeat(100_000) { s.findMatch("a.b.c.d.host${it % 1000}.example${it % 1000}.com") }
        val ms = (System.nanoTime() - t) / 1_000_000
        assertTrue("100k lookups took ${ms}ms", ms < 2000)
    }
}

class RuleParserTest {
    private fun parse(text: String): Pair<List<String>, RuleParser.Stats> {
        val out = mutableListOf<String>()
        val st = RuleParser.parse(text) { out += it }
        return out to st
    }
    @Test fun parsesHostsFormat() {
        val (d, _) = parse("# comment\n127.0.0.1 localhost\n0.0.0.0 Ads.Example.com\n0.0.0.0 a.com b.com # inline\n")
        assertEquals(listOf("ads.example.com", "a.com", "b.com"), d)
    }
    @Test fun parsesPlainAndAdblock() {
        val (d, _) = parse("! title\n[Adblock Plus 2.0]\nplain.example.org\n||block.example.net^\n||opt.example.net^\$important\n")
        assertEquals(listOf("plain.example.org", "block.example.net", "opt.example.net"), d)
    }
    @Test fun rejectsUnsupportedRules() {
        val (d, st) = parse("||x.com/path\n||*.wild.com^\n@@||allow.com^\n##.banner\n/regex/\n1.2.3.4\n||x.com^\$third-party\n")
        assertTrue(d.isEmpty())
        assertTrue(st.rejected > 0)
    }
    @Test fun ipLiteralsAreIgnoredNotRejected() {
        val (d, st) = parse("1.2.3.4\n0.0.0.0 5.6.7.8\n2001:db8::1\nok.example.com\n")
        assertEquals(listOf("ok.example.com"), d); assertEquals(3, st.ignored); assertEquals(0, st.rejected)
    }
    @Test fun survivesGarbage() {
        val rnd = java.util.Random(7)
        val sb = StringBuilder()
        repeat(5000) { sb.append((rnd.nextInt(120) + 1).toChar()) ; if (it % 40 == 0) sb.append('\n') }
        parse(sb.toString())
    }
}
