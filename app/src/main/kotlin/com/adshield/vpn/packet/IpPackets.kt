package com.adshield.vpn.packet

/** A UDP datagram extracted from a tunnel packet. Addresses are raw 4- or 16-byte arrays. */
class UdpPacket(
    val srcAddr: ByteArray,
    val dstAddr: ByteArray,
    val srcPort: Int,
    val dstPort: Int,
    val payload: ByteArray,
) {
    val isIpv6: Boolean get() = srcAddr.size == 16
}

/** A TCP segment seen on the tunnel. [seq]/[ack] are unsigned 32-bit values held in a Long. */
class TcpSegment(
    val srcAddr: ByteArray,
    val dstAddr: ByteArray,
    val srcPort: Int,
    val dstPort: Int,
    val seq: Long,
    val ack: Long,
    val flags: Int,
    val payload: ByteArray,
) {
    val syn: Boolean get() = flags and TcpFlags.SYN != 0
    val fin: Boolean get() = flags and TcpFlags.FIN != 0
    val rst: Boolean get() = flags and TcpFlags.RST != 0
    val hasAck: Boolean get() = flags and TcpFlags.ACK != 0
}

object TcpFlags {
    const val FIN = 0x01
    const val SYN = 0x02
    const val RST = 0x04
    const val PSH = 0x08
    const val ACK = 0x10
}

/**
 * Minimal, strictly bounds-checked IPv4/IPv6 parsing. Unsupported or malformed packets
 * (fragments, IPv6 extension headers, bad lengths) yield null and are dropped.
 */
object IpPacketParser {
    private const val PROTO_TCP = 6
    private const val PROTO_UDP = 17

    sealed interface Result {
        data class Udp(val packet: UdpPacket) : Result
        data class Tcp(val segment: TcpSegment) : Result
    }

    fun parse(buf: ByteArray, length: Int): Result? {
        if (length < 1 || length > buf.size) return null
        return when ((buf[0].toInt() and 0xF0) shr 4) {
            4 -> parseV4(buf, length)
            6 -> parseV6(buf, length)
            else -> null
        }
    }

    private fun u16(b: ByteArray, o: Int) = ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)
    private fun u32(b: ByteArray, o: Int) = (u16(b, o).toLong() shl 16) or u16(b, o + 2).toLong()

    private fun parseV4(b: ByteArray, len: Int): Result? {
        if (len < 20) return null
        val ihl = (b[0].toInt() and 0x0F) * 4
        if (ihl < 20 || ihl > len) return null
        val total = u16(b, 2)
        if (total < ihl || total > len) return null
        if ((u16(b, 6) and 0x3FFF) != 0) return null // fragment (MF flag or offset)
        val src = b.copyOfRange(12, 16)
        val dst = b.copyOfRange(16, 20)
        return parseTransport(b, b[9].toInt() and 0xFF, ihl, total, src, dst)
    }

    private fun parseV6(b: ByteArray, len: Int): Result? {
        if (len < 40) return null
        val total = 40 + u16(b, 4)
        if (total > len) return null
        val src = b.copyOfRange(8, 24)
        val dst = b.copyOfRange(24, 40)
        return parseTransport(b, b[6].toInt() and 0xFF, 40, total, src, dst)
    }

    private fun parseTransport(b: ByteArray, proto: Int, off: Int, end: Int, src: ByteArray, dst: ByteArray): Result? {
        when (proto) {
            PROTO_UDP -> {
                if (end - off < 8) return null
                val udpLen = u16(b, off + 4)
                if (udpLen < 8 || off + udpLen > end) return null
                val payload = b.copyOfRange(off + 8, off + udpLen)
                return Result.Udp(UdpPacket(src, dst, u16(b, off), u16(b, off + 2), payload))
            }
            PROTO_TCP -> {
                if (end - off < 20) return null
                val dataOffset = ((b[off + 12].toInt() and 0xF0) shr 4) * 4
                if (dataOffset < 20 || off + dataOffset > end) return null
                val payload = b.copyOfRange(off + dataOffset, end)
                return Result.Tcp(
                    TcpSegment(src, dst, u16(b, off), u16(b, off + 2), u32(b, off + 4), u32(b, off + 8), b[off + 13].toInt() and 0xFF, payload),
                )
            }
        }
        return null
    }
}

object IpPacketBuilder {
    private const val TTL = 64

    /** Builds the UDP reply for [request]: addresses and ports are swapped. */
    fun udpReply(request: UdpPacket, payload: ByteArray): ByteArray =
        buildUdp(request.dstAddr, request.srcAddr, request.dstPort, request.srcPort, payload)

    fun buildUdp(src: ByteArray, dst: ByteArray, srcPort: Int, dstPort: Int, payload: ByteArray): ByteArray {
        val v6 = src.size == 16
        val ipLen = if (v6) 40 else 20
        val udpLen = 8 + payload.size
        val total = ipLen + udpLen
        require(total <= 0xFFFF) { "payload too large" }
        val p = ByteArray(total)
        writeIpHeader(p, v6, src, dst, protocol = 17, transportLen = udpLen, totalLen = total)
        put16(p, ipLen, srcPort)
        put16(p, ipLen + 2, dstPort)
        put16(p, ipLen + 4, udpLen)
        payload.copyInto(p, ipLen + 8)
        var csum = transportChecksum(p, ipLen, udpLen, src, dst, 17)
        if (csum == 0) csum = 0xFFFF
        put16(p, ipLen + 6, csum)
        return p
    }

    /** RFC 793 reset for a segment that belongs to no session: lets clients fail fast instead of timing out. */
    fun tcpResetFor(seg: TcpSegment): ByteArray =
        if (seg.hasAck) {
            buildTcp(seg.dstAddr, seg.srcAddr, seg.dstPort, seg.srcPort, seg.ack, 0, TcpFlags.RST, ByteArray(0))
        } else {
            val consumed = seg.payload.size + (if (seg.syn) 1 else 0) + (if (seg.fin) 1 else 0)
            buildTcp(seg.dstAddr, seg.srcAddr, seg.dstPort, seg.srcPort, 0, (seg.seq + consumed) and 0xFFFFFFFFL, TcpFlags.RST or TcpFlags.ACK, ByteArray(0))
        }

    @Suppress("LongParameterList") // one parameter per TCP header field is the natural shape of a wire-format builder
    /** Builds a TCP segment (window 65535). [mss] adds the MSS option (only meaningful on SYN segments). */
    fun buildTcp(
        src: ByteArray, dst: ByteArray, srcPort: Int, dstPort: Int,
        seq: Long, ack: Long, flags: Int, payload: ByteArray, mss: Int? = null,
    ): ByteArray {
        val v6 = src.size == 16
        val ipLen = if (v6) 40 else 20
        val tcpHeader = if (mss != null) 24 else 20
        val tcpLen = tcpHeader + payload.size
        val total = ipLen + tcpLen
        require(total <= 0xFFFF) { "segment too large" }
        val p = ByteArray(total)
        writeIpHeader(p, v6, src, dst, protocol = 6, transportLen = tcpLen, totalLen = total)
        put16(p, ipLen, srcPort)
        put16(p, ipLen + 2, dstPort)
        put32(p, ipLen + 4, seq and 0xFFFFFFFFL)
        put32(p, ipLen + 8, ack and 0xFFFFFFFFL)
        p[ipLen + 12] = ((tcpHeader / 4) shl 4).toByte()
        p[ipLen + 13] = flags.toByte()
        put16(p, ipLen + 14, 0xFFFF) // window
        if (mss != null) {
            p[ipLen + 20] = 2; p[ipLen + 21] = 4
            put16(p, ipLen + 22, mss)
        }
        payload.copyInto(p, ipLen + tcpHeader)
        put16(p, ipLen + 16, transportChecksum(p, ipLen, tcpLen, src, dst, 6))
        return p
    }

    private fun writeIpHeader(p: ByteArray, v6: Boolean, src: ByteArray, dst: ByteArray, protocol: Int, transportLen: Int, totalLen: Int) {
        if (v6) {
            p[0] = 0x60
            put16(p, 4, transportLen)
            p[6] = protocol.toByte()
            p[7] = TTL.toByte()
            src.copyInto(p, 8)
            dst.copyInto(p, 24)
        } else {
            p[0] = 0x45
            put16(p, 2, totalLen)
            put16(p, 6, 0x4000) // DF
            p[8] = TTL.toByte()
            p[9] = protocol.toByte()
            src.copyInto(p, 12)
            dst.copyInto(p, 16)
            put16(p, 10, fold(sum(p, 0, 20, 0)))
        }
    }

    /** Ones-complement checksum of [len] bytes at [off], added to [initial]. Returns the un-folded running sum. */
    private fun sum(b: ByteArray, off: Int, len: Int, initial: Long): Long {
        var s = initial
        var i = off
        val end = off + len
        while (i + 1 < end) {
            s += ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) s += (b[i].toInt() and 0xFF) shl 8
        return s
    }

    private fun fold(s: Long): Int {
        var x = s
        while (x shr 16 != 0L) x = (x and 0xFFFF) + (x shr 16)
        return (x.inv() and 0xFFFF).toInt()
    }

    internal fun transportChecksum(p: ByteArray, off: Int, len: Int, src: ByteArray, dst: ByteArray, proto: Int): Int {
        var s = sum(src, 0, src.size, 0)
        s = sum(dst, 0, dst.size, s)
        s += len.toLong()
        s += proto.toLong()
        s = sum(p, off, len, s)
        return fold(s)
    }

    private fun put16(b: ByteArray, o: Int, v: Int) {
        b[o] = (v shr 8).toByte()
        b[o + 1] = v.toByte()
    }

    private fun put32(b: ByteArray, o: Int, v: Long) {
        put16(b, o, (v shr 16).toInt() and 0xFFFF)
        put16(b, o + 2, v.toInt() and 0xFFFF)
    }
}
