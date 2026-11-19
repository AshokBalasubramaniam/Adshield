package com.adshield.vpn.packet

import java.io.ByteArrayOutputStream
import java.security.SecureRandom

/**
 * A deliberately small TCP responder so the virtual DNS server can speak DNS-over-TCP (RFC 7766), which
 * clients use after a truncated UDP answer. It is **not** a general TCP stack:
 *  - only passive opens (the client connects to us), in-order data, no options other than MSS;
 *  - the tunnel is a lossless local pipe, so there is no retransmission timer; out-of-order or duplicate
 *    segments are simply re-ACKed and the client's own retransmission recovers;
 *  - bounded: [maxSessions] concurrent sessions, [idleMillis] idle timeout, 64 KiB per message.
 * Everything is synchronised on this object; all methods are non-blocking.
 */
class TcpDnsSessions(
    private val maxSessions: Int = 64,
    private val idleMillis: Long = 15_000,
    private val now: () -> Long = System::currentTimeMillis,
    private val isn: () -> Long = { SecureRandom().nextInt().toLong() and 0xFFFFFFFFL },
    private val mss: Int = 1360,
) {
    /** A complete DNS message received over TCP, to be answered with [respond]. */
    class Pending(
        val key: String, val message: ByteArray,
        val srcAddr: ByteArray, val dstAddr: ByteArray, val srcPort: Int, val dstPort: Int,
    )

    class Result(val packets: List<ByteArray>, val queries: List<Pending>)

    private enum class State { SYN_RCVD, ESTABLISHED, LAST_ACK }

    private class Session(
        val src: ByteArray, val dst: ByteArray, val srcPort: Int, val dstPort: Int,
        var clientNext: Long, var serverSeq: Long, var lastActive: Long,
    ) {
        var state = State.SYN_RCVD
        val buffer = ByteArrayOutputStream()
        var inflight = 0
        var clientFin = false
    }

    private val sessions = HashMap<String, Session>()

    val size: Int get() = synchronized(this) { sessions.size }

    private fun key(s: TcpSegment) = "${hex(s.srcAddr)}|${s.srcPort}|${hex(s.dstAddr)}|${s.dstPort}"
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun u32(v: Long) = v and 0xFFFFFFFFL

    @Synchronized
    fun onSegment(seg: TcpSegment): Result {
        expire()
        val k = key(seg)
        val out = ArrayList<ByteArray>(2)
        val queries = ArrayList<Pending>(1)
        if (seg.rst) {
            sessions.remove(k)
        } else {
            val s = sessions[k]
            if (s == null) openSession(seg, k, out) else advance(s, seg, k, out, queries)
        }
        return Result(out, queries)
    }

    /** A segment for which no session exists: only a fresh SYN (and only below the cap) is accepted. */
    private fun openSession(seg: TcpSegment, k: String, out: MutableList<ByteArray>) {
        if (seg.syn && !seg.hasAck && sessions.size < maxSessions) {
            val s = Session(seg.srcAddr, seg.dstAddr, seg.srcPort, seg.dstPort, u32(seg.seq + 1), isn(), now())
            sessions[k] = s
            out += synAck(s, s.serverSeq)
            s.serverSeq = u32(s.serverSeq + 1) // the SYN consumes one sequence number
        } else {
            out += IpPacketBuilder.tcpResetFor(seg)
        }
    }

    private fun advance(s: Session, seg: TcpSegment, k: String, out: MutableList<ByteArray>, queries: MutableList<Pending>) {
        s.lastActive = now()
        if (seg.syn) {
            retransmittedSyn(s, seg, k, out)
            return
        }
        if (s.state == State.SYN_RCVD) {
            if (seg.hasAck && seg.ack == s.serverSeq) s.state = State.ESTABLISHED else return
        }
        if (s.state == State.LAST_ACK) {
            if (seg.hasAck && seg.ack == s.serverSeq) sessions.remove(k)
            return
        }
        val needAck = receiveData(s, seg, k, queries) ?: run {
            sessions.remove(k)
            out += buildAck(s, TcpFlags.RST or TcpFlags.ACK)
            return
        }
        finishOrAck(s, needAck, queries.isEmpty(), out)
    }

    private fun retransmittedSyn(s: Session, seg: TcpSegment, k: String, out: MutableList<ByteArray>) {
        if (u32(seg.seq + 1) == s.clientNext && s.state == State.SYN_RCVD) {
            out += synAck(s, u32(s.serverSeq - 1))
        } else {
            sessions.remove(k)
            out += IpPacketBuilder.tcpResetFor(seg)
        }
    }

    /**
     * Applies payload and FIN. Returns whether an ACK is owed, or null on a protocol violation (caller resets).
     * Out-of-order or duplicate data is re-ACKed only; the client retransmits.
     */
    private fun receiveData(s: Session, seg: TcpSegment, k: String, queries: MutableList<Pending>): Boolean? {
        var needAck = false
        if (seg.payload.isNotEmpty()) {
            needAck = true
            if (seg.seq == s.clientNext) {
                s.buffer.write(seg.payload)
                s.clientNext = u32(s.clientNext + seg.payload.size)
                if (!extractMessages(s, k, queries)) return null
            }
        }
        if (seg.fin && u32(seg.seq + seg.payload.size) == s.clientNext) {
            s.clientNext = u32(s.clientNext + 1)
            s.clientFin = true
            needAck = true
        }
        return needAck
    }

    private fun finishOrAck(s: Session, needAck: Boolean, noNewQueries: Boolean, out: MutableList<ByteArray>) {
        if (s.clientFin && s.inflight == 0 && noNewQueries) {
            out += buildAck(s, TcpFlags.FIN or TcpFlags.ACK)
            s.serverSeq = u32(s.serverSeq + 1)
            s.state = State.LAST_ACK
        } else if (needAck) {
            out += buildAck(s, TcpFlags.ACK)
        }
    }

    /** Builds the segments carrying [response] for the query identified by [key]. Empty if the session is gone. */
    @Synchronized
    fun respond(key: String, response: ByteArray): List<ByteArray> {
        val s = sessions[key] ?: return emptyList()
        if (s.inflight > 0) s.inflight--
        s.lastActive = now()
        val framed = ByteArray(2 + response.size)
        framed[0] = (response.size shr 8).toByte()
        framed[1] = response.size.toByte()
        response.copyInto(framed, 2)
        val out = ArrayList<ByteArray>((framed.size + mss - 1) / mss + 1)
        var off = 0
        while (off < framed.size) {
            val n = minOf(mss, framed.size - off)
            val flags = TcpFlags.ACK or if (off + n == framed.size) TcpFlags.PSH else 0
            out += IpPacketBuilder.buildTcp(s.dst, s.src, s.dstPort, s.srcPort, s.serverSeq, s.clientNext, flags, framed.copyOfRange(off, off + n))
            s.serverSeq = u32(s.serverSeq + n)
            off += n
        }
        if (s.clientFin && s.inflight == 0) {
            out += buildAck(s, TcpFlags.FIN or TcpFlags.ACK)
            s.serverSeq = u32(s.serverSeq + 1)
            s.state = State.LAST_ACK
        }
        return out
    }

    /** Parses as many complete length-prefixed messages as the buffer holds. False on a protocol violation. */
    private fun extractMessages(s: Session, k: String, out: MutableList<Pending>): Boolean {
        val data = s.buffer.toByteArray()
        var pos = 0
        while (data.size - pos >= 2) {
            val len = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
            if (len == 0) return false
            if (data.size - pos - 2 < len) break
            out += Pending(k, data.copyOfRange(pos + 2, pos + 2 + len), s.src, s.dst, s.srcPort, s.dstPort)
            s.inflight++
            pos += 2 + len
        }
        s.buffer.reset()
        if (pos < data.size) s.buffer.write(data, pos, data.size - pos)
        return true
    }

    private fun synAck(s: Session, seq: Long) =
        IpPacketBuilder.buildTcp(s.dst, s.src, s.dstPort, s.srcPort, seq, s.clientNext, TcpFlags.SYN or TcpFlags.ACK, ByteArray(0), mss)

    private fun buildAck(s: Session, flags: Int) =
        IpPacketBuilder.buildTcp(s.dst, s.src, s.dstPort, s.srcPort, s.serverSeq, s.clientNext, flags, ByteArray(0))

    private fun expire() {
        val cutoff = now() - idleMillis
        sessions.values.removeAll { it.lastActive < cutoff }
    }
}
