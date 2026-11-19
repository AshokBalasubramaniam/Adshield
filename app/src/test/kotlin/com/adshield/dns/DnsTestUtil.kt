package com.adshield.dns

import java.io.ByteArrayOutputStream

object DnsTestUtil {
    fun query(name: String, type: Int, id: Int = 0x1234, rd: Boolean = true, edns: Int? = null): ByteArray {
        val o = ByteArrayOutputStream()
        fun w16(v: Int) { o.write(v shr 8); o.write(v and 0xFF) }
        w16(id); w16(if (rd) 0x0100 else 0); w16(1); w16(0); w16(0); w16(if (edns != null) 1 else 0)
        name.split('.').filter { it.isNotEmpty() }.forEach { o.write(it.length); o.write(it.toByteArray(Charsets.ISO_8859_1)) }
        o.write(0); w16(type); w16(1)
        if (edns != null) { o.write(0); w16(DnsType.OPT); w16(edns); w16(0); w16(0); w16(0) }
        return o.toByteArray()
    }

    /** Builds an upstream-style response with one A record. */
    fun aResponse(q: ByteArray, ip: ByteArray = byteArrayOf(93, 184.toByte(), 216.toByte(), 34), ttl: Long = 120, rcode: Int = 0): ByteArray {
        val parsed = DnsParser.parseQuery(q)!!
        val o = ByteArrayOutputStream()
        fun w16(v: Int) { o.write(v shr 8); o.write(v and 0xFF) }
        w16(parsed.id); w16(0x8180 or rcode); w16(1); w16(if (rcode == 0) 1 else 0); w16(0); w16(0)
        o.write(q, 12, parsed.questionEnd - 12)
        if (rcode == 0) { w16(0xC00C); w16(1); w16(1); w16((ttl shr 16).toInt()); w16((ttl and 0xFFFF).toInt()); w16(4); o.write(ip) }
        return o.toByteArray()
    }

    private fun encodeName(name: String): ByteArray {
        val o = ByteArrayOutputStream()
        name.split('.').forEach { o.write(it.length); o.write(it.toByteArray(Charsets.ISO_8859_1)) }
        o.write(0)
        return o.toByteArray()
    }

    /** Answer: question-name CNAME -> [chain][0] -> ... -> last, then an A record for the last name (uncompressed owner names). */
    fun cnameResponse(q: ByteArray, chain: List<String>, ip: ByteArray = byteArrayOf(1, 2, 3, 4), ttl: Long = 120): ByteArray {
        val parsed = DnsParser.parseQuery(q)!!
        val o = ByteArrayOutputStream()
        fun w16(v: Int) { o.write(v shr 8); o.write(v and 0xFF) }
        w16(parsed.id); w16(0x8180); w16(1); w16(chain.size + 1); w16(0); w16(0)
        o.write(q, 12, parsed.questionEnd - 12)
        var owner: ByteArray? = null // null = pointer to question name
        for (target in chain) {
            if (owner == null) w16(0xC00C) else o.write(owner)
            w16(5); w16(1); w16((ttl shr 16).toInt()); w16((ttl and 0xFFFF).toInt())
            val rd = encodeName(target)
            w16(rd.size); o.write(rd); owner = rd
        }
        o.write(owner!!); w16(1); w16(1); w16((ttl shr 16).toInt()); w16((ttl and 0xFFFF).toInt()); w16(4); o.write(ip)
        return o.toByteArray()
    }
}
