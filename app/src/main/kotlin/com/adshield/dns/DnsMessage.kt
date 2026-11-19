package com.adshield.dns

import com.adshield.domain.model.BlockMode

object DnsType {
    const val A = 1
    const val AAAA = 28
    const val SVCB = 64
    const val HTTPS = 65
    const val OPT = 41
}

object DnsRcode {
    const val NOERROR = 0
    const val FORMERR = 1
    const val SERVFAIL = 2
    const val NXDOMAIN = 3
    const val NOTIMP = 4
}

/** A validated single-question DNS query. [name] is lower-cased and without trailing dot. */
class DnsQuery(
    val raw: ByteArray,
    val id: Int,
    val flags: Int,
    val name: String,
    val type: Int,
    val qclass: Int,
    /** Offset one past the question section. */
    val questionEnd: Int,
) {
    val opcode: Int get() = (flags shr 11) and 0xF
}

/**
 * Defensive DNS wire-format handling. Every read is bounds-checked and every function returns null
 * (never throws) on malformed input, so hostile or corrupt packets cannot crash the service.
 */
object DnsParser {
    const val HEADER_SIZE = 12
    private const val MAX_NAME_WIRE = 255

    fun u16(b: ByteArray, off: Int): Int = ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)
    private fun u32(b: ByteArray, off: Int): Long = (u16(b, off).toLong() shl 16) or u16(b, off + 2).toLong()

    fun parseQuery(data: ByteArray): DnsQuery? {
        if (data.size < HEADER_SIZE + 5) return null
        val flags = u16(data, 2)
        if (flags and 0x8000 != 0) return null // a response, not a query
        if (u16(data, 4) != 1) return null // exactly one question supported
        var pos = HEADER_SIZE
        val name = StringBuilder()
        var wireLen = 1
        while (true) {
            if (pos >= data.size) return null
            val len = data[pos].toInt() and 0xFF
            if (len == 0) {
                pos++
                break
            }
            // Compression pointers / extended labels never occur in a genuine question.
            if (len and 0xC0 != 0 || len > 63 || pos + 1 + len > data.size) return null
            wireLen += len + 1
            if (wireLen > MAX_NAME_WIRE) return null
            if (name.isNotEmpty()) name.append('.')
            for (i in 0 until len) {
                var c = data[pos + 1 + i].toInt() and 0xFF
                if (c < 0x21 || c > 0x7E) return null
                if (c in 'A'.code..'Z'.code) c += 32
                name.append(c.toChar())
            }
            pos += 1 + len
        }
        if (pos + 4 > data.size) return null
        return DnsQuery(
            raw = data,
            id = u16(data, 0),
            flags = flags,
            name = name.toString(),
            type = u16(data, pos),
            qclass = u16(data, pos + 2),
            questionEnd = pos + 4,
        )
    }

    fun rcode(response: ByteArray): Int = if (response.size >= HEADER_SIZE) response[3].toInt() and 0x0F else DnsRcode.SERVFAIL

    fun isTruncated(response: ByteArray): Boolean = response.size >= HEADER_SIZE && (response[2].toInt() and 0x02) != 0

    /** Smallest TTL among answer and authority records, or null when absent or the message is malformed. */
    fun minTtl(response: ByteArray): Long? {
        if (response.size < HEADER_SIZE) return null
        val qd = u16(response, 4)
        val records = u16(response, 6) + u16(response, 8)
        var pos = HEADER_SIZE
        repeat(qd) {
            pos = skipName(response, pos) ?: return null
            pos += 4
            if (pos > response.size) return null
        }
        var min: Long? = null
        repeat(records) {
            pos = skipName(response, pos) ?: return null
            if (pos + 10 > response.size) return null
            val ttl = u32(response, pos + 4)
            val rdLen = u16(response, pos + 8)
            pos += 10 + rdLen
            if (pos > response.size) return null
            min = if (min == null) ttl else minOf(min!!, ttl)
        }
        return min
    }

    private fun skipName(b: ByteArray, start: Int): Int? {
        var pos = start
        var hops = 0
        while (hops++ < 128) {
            if (pos >= b.size) return null
            val len = b[pos].toInt() and 0xFF
            when {
                len == 0 -> return pos + 1
                len and 0xC0 == 0xC0 -> return if (pos + 2 <= b.size) pos + 2 else null
                len and 0xC0 != 0 -> return null
                else -> pos += 1 + len
            }
        }
        return null
    }

    private const val TYPE_CNAME = 5
    private const val MAX_POINTER_HOPS = 16
    private const val MAX_NAME_CHARS = 253
    private val NO_NAMES: List<String> = emptyList()

    /**
     * Targets of CNAME records in the answer section, lower-cased. Fully bounds-checked: compression pointers
     * may not loop (hop cap), names are length-limited and syntax-validated; anything malformed is skipped,
     * never thrown. Returns a shared empty list (no allocation) in the common no-CNAME case.
     */
    fun cnameTargets(response: ByteArray): List<String> {
        if (response.size < HEADER_SIZE + 5) return NO_NAMES
        val answers = u16(response, 6)
        if (answers == 0) return NO_NAMES
        var pos = HEADER_SIZE
        repeat(u16(response, 4)) {
            pos = skipName(response, pos) ?: return NO_NAMES
            pos += 4
            if (pos > response.size) return NO_NAMES
        }
        var out: ArrayList<String>? = null
        repeat(minOf(answers, 64)) {
            pos = skipName(response, pos) ?: return out ?: NO_NAMES
            if (pos + 10 > response.size) return out ?: NO_NAMES
            val type = u16(response, pos)
            val rdLen = u16(response, pos + 8)
            val rdStart = pos + 10
            if (rdStart + rdLen > response.size) return out ?: NO_NAMES
            if (type == TYPE_CNAME) {
                readName(response, rdStart)?.let { name ->
                    if (out == null) out = ArrayList(2)
                    out!!.add(name)
                }
            }
            pos = rdStart + rdLen
        }
        return out ?: NO_NAMES
    }

    /** Decodes a (possibly compressed) name; null if malformed, looping, too long or syntactically invalid. */
    private fun readName(msg: ByteArray, start: Int): String? {
        val sb = StringBuilder()
        var pos = start
        var hops = 0
        while (true) {
            if (pos >= msg.size) return null
            val len = msg[pos].toInt() and 0xFF
            when {
                len == 0 -> return if (sb.isEmpty()) null else com.adshield.engine.DomainNormalizer.normalize(sb.toString())
                len and 0xC0 == 0xC0 -> {
                    if (pos + 2 > msg.size || ++hops > MAX_POINTER_HOPS) return null
                    val target = ((len and 0x3F) shl 8) or (msg[pos + 1].toInt() and 0xFF)
                    if (target >= msg.size) return null
                    pos = target
                }
                len and 0xC0 != 0 || len > 63 || pos + 1 + len > msg.size -> return null
                else -> {
                    if (sb.length + len + 1 > MAX_NAME_CHARS) return null
                    if (sb.isNotEmpty()) sb.append('.')
                    for (i in 0 until len) sb.append((msg[pos + 1 + i].toInt() and 0xFF).toChar())
                    pos += 1 + len
                }
            }
        }
    }

    /** Offset one past the first question of [msg], or null if malformed. */
    fun questionEndOf(msg: ByteArray): Int? {
        if (msg.size < HEADER_SIZE || u16(msg, 4) < 1) return null
        val end = skipName(msg, HEADER_SIZE)?.plus(4) ?: return null
        return if (end <= msg.size) end else null
    }

    /** Returns the OPT-advertised UDP payload size, or 512 if the client sent no EDNS. */
    fun clientUdpLimit(query: ByteArray): Int {
        if (query.size < HEADER_SIZE) return 512
        val qd = u16(query, 4)
        val rrs = u16(query, 6) + u16(query, 8) + u16(query, 10)
        var pos = HEADER_SIZE
        repeat(qd) {
            pos = skipName(query, pos) ?: return 512
            pos += 4
        }
        repeat(rrs) {
            pos = skipName(query, pos) ?: return 512
            if (pos + 10 > query.size) return 512
            if (u16(query, pos) == DnsType.OPT) return maxOf(512, u16(query, pos + 2))
            pos += 10 + u16(query, pos + 8)
        }
        return 512
    }
}

object DnsResponseBuilder {
    private const val BLOCK_TTL = 60

    private fun header(query: DnsQuery, rcode: Int, answers: Int): ByteArray {
        val h = ByteArray(DnsParser.HEADER_SIZE)
        h[0] = (query.id shr 8).toByte()
        h[1] = query.id.toByte()
        val rd = query.flags and 0x0100
        val flags = 0x8000 or rd or 0x0080 or (rcode and 0xF)
        h[2] = (flags shr 8).toByte()
        h[3] = flags.toByte()
        h[5] = 1 // QDCOUNT
        h[7] = answers.toByte()
        return h
    }

    private fun question(query: DnsQuery): ByteArray = query.raw.copyOfRange(DnsParser.HEADER_SIZE, query.questionEnd)

    /** Response for a blocked name according to [mode]. Always echoes the original question bytes. */
    fun blocked(query: DnsQuery, mode: BlockMode): ByteArray {
        if (mode == BlockMode.NXDOMAIN) return header(query, DnsRcode.NXDOMAIN, 0) + question(query)
        val rdata = when (query.type) {
            DnsType.A -> ByteArray(4)
            DnsType.AAAA -> ByteArray(16)
            else -> return header(query, DnsRcode.NOERROR, 0) + question(query) // NODATA for HTTPS/SVCB/TXT/...
        }
        val answer = ByteArray(12 + rdata.size)
        answer[0] = 0xC0.toByte()
        answer[1] = 0x0C // pointer to the question name
        answer[2] = (query.type shr 8).toByte()
        answer[3] = query.type.toByte()
        answer[4] = 0
        answer[5] = 1 // class IN
        answer[6] = (BLOCK_TTL ushr 24).toByte()
        answer[7] = (BLOCK_TTL ushr 16).toByte()
        answer[8] = (BLOCK_TTL ushr 8).toByte()
        answer[9] = BLOCK_TTL.toByte()
        answer[10] = (rdata.size shr 8).toByte()
        answer[11] = rdata.size.toByte()
        rdata.copyInto(answer, 12)
        return header(query, DnsRcode.NOERROR, 1) + question(query) + answer
    }

    /** Header + question with TC=1, used when a response would not fit in the client's UDP buffer. */
    fun truncate(response: ByteArray): ByteArray? {
        val end = DnsParser.questionEndOf(response) ?: return null
        val out = response.copyOf(end)
        out[2] = (out[2].toInt() or 0x02).toByte()
        for (i in 6..11) out[i] = 0 // AN, NS, AR counts
        return out
    }

    fun error(query: DnsQuery, rcode: Int): ByteArray = header(query, rcode, 0) + question(query)

    /** FORMERR for garbage we can at least attribute to a transaction id; null if even that is impossible. */
    fun formErr(raw: ByteArray): ByteArray? {
        if (raw.size < 2) return null
        val h = ByteArray(DnsParser.HEADER_SIZE)
        h[0] = raw[0]
        h[1] = raw[1]
        h[2] = 0x80.toByte()
        h[3] = DnsRcode.FORMERR.toByte()
        return h
    }
}
