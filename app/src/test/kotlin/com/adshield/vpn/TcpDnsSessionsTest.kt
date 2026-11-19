package com.adshield.vpn

import com.adshield.vpn.packet.IpPacketBuilder
import com.adshield.vpn.packet.IpPacketParser
import com.adshield.vpn.packet.TcpDnsSessions
import com.adshield.vpn.packet.TcpFlags
import com.adshield.vpn.packet.TcpSegment
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Random

class TcpDnsSessionsTest {
    private val client = byteArrayOf(10, 111, 222.toByte(), 1)
    private val server = byteArrayOf(10, 111, 222.toByte(), 2)
    private var clock = 0L
    private fun sessions(max: Int = 64, isn: Long = 5000L, mss: Int = 1360) = TcpDnsSessions(max, 15_000, { clock }, { isn }, mss)

    private fun seg(flags: Int, seq: Long, ack: Long = 0, payload: ByteArray = ByteArray(0), port: Int = 40000, src: ByteArray = client, dst: ByteArray = server): TcpSegment {
        val pkt = IpPacketBuilder.buildTcp(src, dst, port, 53, seq, ack, flags, payload)
        return (IpPacketParser.parse(pkt, pkt.size) as IpPacketParser.Result.Tcp).segment
    }
    private fun parse(p: ByteArray) = (IpPacketParser.parse(p, p.size) as IpPacketParser.Result.Tcp).segment
    private fun framed(msg: ByteArray) = byteArrayOf((msg.size shr 8).toByte(), msg.size.toByte()) + msg

    /** Performs the handshake and returns the server's ISN+1 (the next sequence number it will use). */
    private fun connect(s: TcpDnsSessions, clientIsn: Long = 1000, port: Int = 40000): Long {
        val synAck = parse(s.onSegment(seg(TcpFlags.SYN, clientIsn, port = port)).packets.single())
        assertEquals(TcpFlags.SYN or TcpFlags.ACK, synAck.flags); assertEquals(clientIsn + 1, synAck.ack)
        s.onSegment(seg(TcpFlags.ACK, clientIsn + 1, synAck.seq + 1, port = port))
        return synAck.seq + 1
    }

    @Test fun handshakeProducesValidSynAckWithMss() {
        val s = sessions()
        val raw = s.onSegment(seg(TcpFlags.SYN, 1000)).packets.single()
        val synAck = parse(raw)
        assertEquals(5000L, synAck.seq); assertEquals(1001L, synAck.ack)
        assertEquals(24, raw.size - 20) // 20-byte header + MSS option
        assertEquals(0, IpPacketBuilder.transportChecksum(raw, 20, raw.size - 20, server, client, 6))
        assertEquals(1, s.size)
    }

    @Test fun synRetransmitGetsSameSynAck() {
        val s = sessions()
        val a = parse(s.onSegment(seg(TcpFlags.SYN, 1000)).packets.single())
        val b = parse(s.onSegment(seg(TcpFlags.SYN, 1000)).packets.single())
        assertEquals(a.seq, b.seq)
    }

    @Test fun queryIsAckedThenAnsweredWithLengthPrefixAndPsh() {
        val s = sessions(); val next = connect(s)
        val msg = ByteArray(40) { it.toByte() }
        val r = s.onSegment(seg(TcpFlags.PSH or TcpFlags.ACK, 1001, next, framed(msg)))
        val ack = parse(r.packets.single())
        assertEquals(TcpFlags.ACK, ack.flags); assertEquals(1001L + 42, ack.ack)
        assertArrayEquals(msg, r.queries.single().message)
        val resp = ByteArray(100) { (it + 1).toByte() }
        val out = s.respond(r.queries.single().key, resp).map(::parse)
        assertEquals(1, out.size)
        assertEquals(TcpFlags.PSH or TcpFlags.ACK, out[0].flags); assertEquals(next, out[0].seq); assertEquals(1001L + 42, out[0].ack)
        assertArrayEquals(framed(resp), out[0].payload)
    }

    @Test fun queryLengthPrefixAndBodySplitAcrossSegments() {
        val s = sessions(); val next = connect(s)
        val f = framed(ByteArray(30) { 7 })
        assertTrue(s.onSegment(seg(TcpFlags.ACK, 1001, next, f.copyOfRange(0, 1))).queries.isEmpty())
        assertTrue(s.onSegment(seg(TcpFlags.ACK, 1002, next, f.copyOfRange(1, 10))).queries.isEmpty())
        val done = s.onSegment(seg(TcpFlags.ACK, 1011, next, f.copyOfRange(10, f.size)))
        assertEquals(30, done.queries.single().message.size)
    }

    @Test fun pipelinedQueriesInOneSegmentAreBothDelivered() {
        val s = sessions(); val next = connect(s)
        val r = s.onSegment(seg(TcpFlags.ACK, 1001, next, framed(byteArrayOf(1, 1)) + framed(byteArrayOf(2, 2, 2))))
        assertEquals(listOf(2, 3), r.queries.map { it.message.size })
    }

    @Test fun largeResponseIsChunkedToMssWithContiguousSequenceNumbers() {
        val s = sessions(mss = 1000); val next = connect(s)
        val q = s.onSegment(seg(TcpFlags.ACK, 1001, next, framed(ByteArray(20)))).queries.single()
        val resp = ByteArray(3000) { (it % 251).toByte() }
        val segs = s.respond(q.key, resp).map(::parse)
        assertEquals(4, segs.size) // 3002 framed bytes / 1000
        var expect = next
        segs.forEach { assertEquals(expect, it.seq); assertTrue(it.payload.size <= 1000); expect += it.payload.size }
        assertArrayEquals(framed(resp), segs.flatMap { it.payload.toList() }.toByteArray())
        assertTrue(segs.last().flags and TcpFlags.PSH != 0 && segs.first().flags and TcpFlags.PSH == 0)
    }

    @Test fun clientFinAfterResponseIsAnsweredWithFinAndSessionEndsOnFinalAck() {
        val s = sessions(); val next = connect(s)
        val q = s.onSegment(seg(TcpFlags.ACK, 1001, next, framed(ByteArray(20)))).queries.single()
        s.respond(q.key, ByteArray(10))
        val serverSeq = next + 12
        val r = s.onSegment(seg(TcpFlags.FIN or TcpFlags.ACK, 1001 + 22, serverSeq))
        val fin = parse(r.packets.single())
        assertTrue(fin.fin && fin.hasAck); assertEquals(1001L + 22 + 1, fin.ack); assertEquals(serverSeq, fin.seq)
        s.onSegment(seg(TcpFlags.ACK, 1001 + 23, serverSeq + 1))
        assertEquals(0, s.size)
    }

    @Test fun clientFinWhileQueryInFlightDefersOurFinUntilAfterTheResponse() {
        val s = sessions(); val next = connect(s)
        val q = s.onSegment(seg(TcpFlags.FIN or TcpFlags.ACK, 1001, next, framed(ByteArray(20)))).also {
            assertTrue("only an ACK, no FIN yet", it.packets.none { p -> parse(p).fin })
        }.queries.single()
        val out = s.respond(q.key, ByteArray(10)).map(::parse)
        assertTrue(out.first().payload.isNotEmpty()); assertTrue(out.last().fin)
    }

    @Test fun strayAndUnknownSegmentsGetReset() {
        val s = sessions()
        val rst = parse(s.onSegment(seg(TcpFlags.ACK, 10, 99)).packets.single())
        assertEquals(TcpFlags.RST, rst.flags); assertEquals(99L, rst.seq)
        assertEquals(0, s.size)
    }

    @Test fun clientRstRemovesSessionSilently() {
        val s = sessions(); connect(s)
        assertTrue(s.onSegment(seg(TcpFlags.RST, 1001)).packets.isEmpty()); assertEquals(0, s.size)
    }

    @Test fun sessionCapRefusesNewConnectionsWithReset() {
        val s = sessions(max = 2)
        connect(s, port = 1); connect(s, port = 2)
        val r = parse(s.onSegment(seg(TcpFlags.SYN, 5, port = 3)).packets.single())
        assertTrue(r.rst); assertEquals(2, s.size)
    }

    @Test fun idleSessionsExpire() {
        val s = sessions(); connect(s); assertEquals(1, s.size)
        clock = 16_000
        s.onSegment(seg(TcpFlags.SYN, 7, port = 9)) // any activity triggers cleanup
        assertEquals(1, s.size) // only the new one
    }

    @Test fun zeroLengthMessageIsAProtocolErrorAndResets() {
        val s = sessions(); val next = connect(s)
        val r = s.onSegment(seg(TcpFlags.ACK, 1001, next, byteArrayOf(0, 0)))
        assertTrue(parse(r.packets.single()).rst); assertEquals(0, s.size); assertTrue(r.queries.isEmpty())
    }

    @Test fun duplicateAndOutOfOrderDataIsReAckedNotReDelivered() {
        val s = sessions(); val next = connect(s)
        val f = framed(ByteArray(10))
        assertEquals(1, s.onSegment(seg(TcpFlags.ACK, 1001, next, f)).queries.size)
        val dup = s.onSegment(seg(TcpFlags.ACK, 1001, next, f))
        assertTrue(dup.queries.isEmpty()); assertEquals(1001L + 12, parse(dup.packets.single()).ack)
        val gap = s.onSegment(seg(TcpFlags.ACK, 5000, next, f))
        assertTrue(gap.queries.isEmpty()); assertEquals(1001L + 12, parse(gap.packets.single()).ack)
    }

    @Test fun respondOnUnknownSessionIsEmpty() = assertTrue(sessions().respond("nope", ByteArray(10)).isEmpty())

    @Test fun sequenceNumbersWrapAround32Bits() {
        val s = sessions(isn = 0xFFFFFFFEL); val clientIsn = 0xFFFFFFF0L
        val synAck = parse(s.onSegment(seg(TcpFlags.SYN, clientIsn)).packets.single())
        assertEquals(0xFFFFFFF1L, synAck.ack)
        val serverNext = (synAck.seq + 1) and 0xFFFFFFFFL
        s.onSegment(seg(TcpFlags.ACK, 0xFFFFFFF1L, serverNext))
        val q = s.onSegment(seg(TcpFlags.ACK, 0xFFFFFFF1L, serverNext, framed(ByteArray(40)))).queries.single()
        val resp = parse(s.respond(q.key, ByteArray(5)).single())
        assertEquals(serverNext, resp.seq)
        assertEquals((0xFFFFFFF1L + 42) and 0xFFFFFFFFL, resp.ack)
    }

    @Test fun ipv6SessionsWorkAndChecksumsAreValid() {
        val c6 = ByteArray(16).also { it[0] = 0xfd.toByte(); it[15] = 1 }; val s6 = ByteArray(16).also { it[0] = 0xfd.toByte(); it[15] = 2 }
        val s = sessions()
        val raw = s.onSegment(seg(TcpFlags.SYN, 1, src = c6, dst = s6)).packets.single()
        assertEquals(0, IpPacketBuilder.transportChecksum(raw, 40, raw.size - 40, s6, c6, 6))
        assertNotNull(parse(raw))
    }

    @Test fun randomSegmentSequencesNeverThrow() {
        val rnd = Random(11); val s = sessions(max = 8)
        repeat(20_000) {
            val flags = rnd.nextInt(0x40)
            val payload = ByteArray(rnd.nextInt(40)).also { rnd.nextBytes(it) }
            val r = s.onSegment(seg(flags, rnd.nextInt().toLong() and 0xFFFFFFFFL, rnd.nextInt().toLong() and 0xFFFFFFFFL, payload, port = 1 + rnd.nextInt(4)))
            r.queries.forEach { q -> if (rnd.nextBoolean()) s.respond(q.key, ByteArray(rnd.nextInt(3000))) }
        }
        assertFalse(s.size > 8)
    }
}
