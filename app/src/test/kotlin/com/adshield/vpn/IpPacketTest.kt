package com.adshield.vpn

import com.adshield.vpn.packet.IpPacketBuilder
import com.adshield.vpn.packet.IpPacketParser
import com.adshield.vpn.packet.TcpFlags
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Random

class IpPacketTest {
    private val v4c = byteArrayOf(10, 111, 222.toByte(), 1); private val v4s = byteArrayOf(10, 111, 222.toByte(), 2)
    private val v6c = ByteArray(16).also { it[0] = 0xfd.toByte(); it[15] = 1 }
    private val v6s = ByteArray(16).also { it[0] = 0xfd.toByte(); it[15] = 2 }
    private val payload = ByteArray(33) { it.toByte() } // odd length exercises checksum padding

    private fun check(src: ByteArray, dst: ByteArray) {
        val pkt = IpPacketBuilder.buildUdp(src, dst, 40000, 53, payload)
        val u = (IpPacketParser.parse(pkt, pkt.size) as IpPacketParser.Result.Udp).packet
        assertArrayEquals(src, u.srcAddr); assertArrayEquals(dst, u.dstAddr)
        assertEquals(40000, u.srcPort); assertEquals(53, u.dstPort); assertArrayEquals(payload, u.payload)
        val ipLen = if (src.size == 16) 40 else 20
        // A correct UDP checksum sums (with pseudo header) to zero.
        assertEquals(0, IpPacketBuilder.transportChecksum(pkt, ipLen, pkt.size - ipLen, src, dst, 17))
        if (src.size == 4) assertEquals(0, rawHeaderSum(pkt)) // valid IPv4 header checksum
        val reply = IpPacketBuilder.udpReply(u, byteArrayOf(1, 2, 3))
        val r = (IpPacketParser.parse(reply, reply.size) as IpPacketParser.Result.Udp).packet
        assertArrayEquals(dst, r.srcAddr); assertArrayEquals(src, r.dstAddr); assertEquals(53, r.srcPort); assertEquals(40000, r.dstPort)
    }
    private fun rawHeaderSum(p: ByteArray): Int { var s = 0L; for (i in 0 until 20 step 2) s += ((p[i].toInt() and 0xFF) shl 8) or (p[i + 1].toInt() and 0xFF); while (s shr 16 != 0L) s = (s and 0xFFFF) + (s shr 16); return (s.inv() and 0xFFFF).toInt() }

    @Test fun udpV4RoundTrip() = check(v4c, v4s)
    @Test fun udpV6RoundTrip() = check(v6c, v6s)

    @Test fun tcpSynGetsRst() {
        val syn = IpPacketBuilder.buildTcp(v4c, v4s, 40000, 853, 9, 0, TcpFlags.SYN, ByteArray(0), mss = 1400)
        val seg = (IpPacketParser.parse(syn, syn.size) as IpPacketParser.Result.Tcp).segment
        assertEquals(853, seg.dstPort); assertEquals(9L, seg.seq); assertTrue(seg.syn && !seg.hasAck)
        val rst = IpPacketBuilder.tcpResetFor(seg)
        assertEquals(TcpFlags.RST or TcpFlags.ACK, rst[33].toInt() and 0xFF); assertEquals(10, rst[31].toInt()) // ack = seq+1
        assertEquals(0, IpPacketBuilder.transportChecksum(rst, 20, 20, v4s, v4c, 6))
    }

    @Test fun tcpParsingKeepsFlagsSeqAckAndPayload() {
        val pkt = IpPacketBuilder.buildTcp(v6c, v6s, 1234, 53, 0xFFFFFFF0L, 77, TcpFlags.PSH or TcpFlags.ACK, byteArrayOf(1, 2, 3))
        val s = (IpPacketParser.parse(pkt, pkt.size) as IpPacketParser.Result.Tcp).segment
        assertEquals(0xFFFFFFF0L, s.seq); assertEquals(77L, s.ack); assertTrue(s.hasAck && !s.syn && !s.fin)
        assertArrayEquals(byteArrayOf(1, 2, 3), s.payload)
        assertEquals(0, IpPacketBuilder.transportChecksum(pkt, 40, pkt.size - 40, v6c, v6s, 6))
    }

    @Test fun resetForAckedSegmentUsesItsAckAsSequence() {
        val pkt = IpPacketBuilder.buildTcp(v4c, v4s, 5, 53, 100, 555, TcpFlags.ACK, ByteArray(0))
        val s = (IpPacketParser.parse(pkt, pkt.size) as IpPacketParser.Result.Tcp).segment
        val rst = (IpPacketParser.parse(IpPacketBuilder.tcpResetFor(s), 40) as IpPacketParser.Result.Tcp).segment
        assertEquals(555L, rst.seq); assertEquals(TcpFlags.RST, rst.flags)
    }

    @Test fun badTcpDataOffsetIsRejected() {
        val pkt = IpPacketBuilder.buildTcp(v4c, v4s, 5, 53, 1, 0, TcpFlags.ACK, ByteArray(4))
        assertNull(IpPacketParser.parse(pkt.copyOf().also { it[32] = 0x40 }, pkt.size)) // offset < 20
        assertNull(IpPacketParser.parse(pkt.copyOf().also { it[32] = 0xF0.toByte() }, pkt.size)) // offset beyond packet
    }

    @Test fun rejectsFragmentsAndBadLengths() {
        val pkt = IpPacketBuilder.buildUdp(v4c, v4s, 1, 53, payload)
        assertNull(IpPacketParser.parse(pkt.copyOf().also { it[6] = 0x20 }, pkt.size)) // MF set
        assertNull(IpPacketParser.parse(pkt.copyOf().also { it[7] = 8 }, pkt.size)) // frag offset
        assertNull(IpPacketParser.parse(pkt, pkt.size - 1)) // shorter than total length
        assertNull(IpPacketParser.parse(pkt.copyOf().also { it[0] = 0x4F }, pkt.size)) // ihl beyond packet
        assertNull(IpPacketParser.parse(pkt.copyOf().also { it[0] = 0x44 }, pkt.size)) // ihl < 20
        assertNull(IpPacketParser.parse(pkt.copyOf().also { it[25] = 3 }, pkt.size)) // udp len < 8
        assertNull(IpPacketParser.parse(pkt.copyOf().also { it[24] = 0x7F }, pkt.size)) // udp len beyond packet
    }

    @Test fun ignoresOtherProtocolsAndExtensionHeaders() {
        val v6 = IpPacketBuilder.buildUdp(v6c, v6s, 1, 53, payload)
        assertNull(IpPacketParser.parse(v6.copyOf().also { it[6] = 0 }, v6.size)) // hop-by-hop ext header
        val icmp = IpPacketBuilder.buildUdp(v4c, v4s, 1, 53, payload).also { it[9] = 1 }
        assertNull(IpPacketParser.parse(icmp, icmp.size))
    }

    private fun ipVersionByte(i: Int): Byte = (if (i % 4 == 0) 0x45 else 0x60).toByte()

    @Test fun neverThrowsOnRandomOrMutatedPackets() {
        val rnd = Random(99)
        repeat(30_000) {
            val b = ByteArray(rnd.nextInt(120))
            rnd.nextBytes(b)
            if (b.isNotEmpty() && it % 2 == 0) b[0] = ipVersionByte(it)
            IpPacketParser.parse(b, b.size)
            IpPacketParser.parse(b, b.size + 5)
        }
        val base = IpPacketBuilder.buildUdp(v6c, v6s, 1, 53, payload)
        repeat(30_000) { val b = base.copyOf(); b[rnd.nextInt(b.size)] = rnd.nextInt().toByte(); IpPacketParser.parse(b, b.size) }
        assertTrue(true)
    }
}
