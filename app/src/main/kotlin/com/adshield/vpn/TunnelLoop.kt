package com.adshield.vpn

import android.os.ParcelFileDescriptor
import com.adshield.dns.DnsParser
import com.adshield.dns.DnsQueryProcessor
import com.adshield.dns.DnsResponseBuilder
import com.adshield.vpn.packet.IpPacketBuilder
import com.adshield.vpn.packet.IpPacketParser
import com.adshield.vpn.packet.TcpDnsSessions
import com.adshield.vpn.packet.TcpSegment
import com.adshield.vpn.packet.UdpPacket
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.withContext
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException

/** Maps a flow to the app that owns the socket, if Android reveals it. Arguments: protocol, src, srcPort, dst, dstPort. */
fun interface Attribution {
    fun owner(protocol: Int, src: ByteArray, srcPort: Int, dst: ByteArray, dstPort: Int): String?
}

/**
 * Reads packets from the tunnel and serves DNS over UDP/53 and TCP/53. TCP to any other port on a captured
 * address is reset (so DoT/DoH-to-IP clients fall back quickly), other UDP is dropped; both are reported to
 * [observer] as possible DNS-bypass attempts. Concurrency is bounded: when too many queries are in flight,
 * new ones are dropped and the client's resolver simply retries.
 *
 * [run] returns normally when the interface dies by itself (the caller should recover) and throws
 * CancellationException when cancelled (it closes [pfd] first, which unblocks the blocking read).
 */
class TunnelLoop(
    private val processor: DnsQueryProcessor,
    private val attribution: Attribution,
    private val observer: TunnelObserver = TunnelObserver.NONE,
) {
    private val tcp = TcpDnsSessions()

    suspend fun run(pfd: ParcelFileDescriptor) = coroutineScope {
        val input = FileInputStream(pfd.fileDescriptor)
        val output = FileOutputStream(pfd.fileDescriptor)
        val outbound = Channel<ByteArray>(OUT_CAPACITY)
        val inflight = Semaphore(MAX_INFLIGHT)

        val writer = launch(Dispatchers.IO) {
            try {
                for (packet in outbound) output.write(packet)
            } catch (_: IOException) {
                // interface closed
            }
        }

        val reader = launch(Dispatchers.IO) {
            val readScope: CoroutineScope = this
            val buf = ByteArray(BUFFER)
            try {
                while (isActive) {
                    val n = input.read(buf)
                    if (n < 0) break
                    if (n == 0) continue
                    handle(buf, n, outbound, inflight, readScope)
                }
            } catch (_: IOException) {
                // closed by us (stop) or by the system (revoke); caller decides what to do
            }
        }

        try {
            reader.join()
        } finally {
            withContext(NonCancellable) {
                runCatching { pfd.close() }
                reader.join()
                outbound.close()
                writer.join()
            }
        }
    }

    private fun handle(buf: ByteArray, n: Int, outbound: Channel<ByteArray>, inflight: Semaphore, scope: CoroutineScope) {
        when (val parsed = IpPacketParser.parse(buf, n)) {
            is IpPacketParser.Result.Udp -> handleUdp(parsed.packet, outbound, inflight, scope)
            is IpPacketParser.Result.Tcp -> handleTcp(parsed.segment, outbound, inflight, scope)
            null -> Unit
        }
    }

    private fun handleUdp(packet: UdpPacket, outbound: Channel<ByteArray>, inflight: Semaphore, scope: CoroutineScope) {
        if (packet.dstPort != DNS_PORT) {
            observer.onDroppedUdp(packet.dstAddr, packet.dstPort)
            return
        }
        if (!VpnConfig.isVirtualDns(packet.dstAddr)) observer.onHardcodedResolverQuery(packet.dstAddr)
        if (!inflight.tryAcquire()) return
        scope.launch(Dispatchers.Default) {
            try {
                answerUdp(packet, outbound)
            } finally {
                inflight.release()
            }
        }
    }

    private fun handleTcp(seg: TcpSegment, outbound: Channel<ByteArray>, inflight: Semaphore, scope: CoroutineScope) {
        if (seg.dstPort != DNS_PORT) {
            if (seg.syn && !seg.hasAck) observer.onRefusedTcp(seg.dstAddr, seg.dstPort)
            if (!seg.rst) outbound.trySend(IpPacketBuilder.tcpResetFor(seg))
            return
        }
        if (seg.syn && !seg.hasAck && !VpnConfig.isVirtualDns(seg.dstAddr)) observer.onHardcodedResolverQuery(seg.dstAddr)
        val result = tcp.onSegment(seg)
        result.packets.forEach { outbound.trySend(it) }
        for (q in result.queries) {
            if (!inflight.tryAcquire()) continue
            scope.launch(Dispatchers.Default) {
                try {
                    val owner = attribution.owner(PROTO_TCP, q.srcAddr, q.srcPort, q.dstAddr, q.dstPort)
                    val response = processor.process(q.message, owner) ?: return@launch
                    tcp.respond(q.key, response).forEach { outbound.trySend(it) }
                } finally {
                    inflight.release()
                }
            }
        }
    }

    private suspend fun answerUdp(packet: UdpPacket, outbound: Channel<ByteArray>) {
        val owner = attribution.owner(PROTO_UDP, packet.srcAddr, packet.srcPort, packet.dstAddr, packet.dstPort)
        val response = processor.process(packet.payload, owner) ?: return
        val mtuLimit = VpnConfig.MTU - if (packet.isIpv6) 48 else 28
        val limit = minOf(mtuLimit, DnsParser.clientUdpLimit(packet.payload))
        val payload = if (response.size > limit) DnsResponseBuilder.truncate(response) ?: return else response
        outbound.trySend(IpPacketBuilder.udpReply(packet, payload))
    }

    private companion object {
        const val DNS_PORT = 53
        const val PROTO_UDP = 17
        const val PROTO_TCP = 6
        const val BUFFER = 32 * 1024
        const val OUT_CAPACITY = 256
        const val MAX_INFLIGHT = 64
    }
}
