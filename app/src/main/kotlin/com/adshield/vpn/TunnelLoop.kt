package com.adshield.vpn

import android.os.ParcelFileDescriptor
import com.adshield.dns.DnsParser
import com.adshield.dns.DnsQueryProcessor
import com.adshield.dns.DnsResponseBuilder
import com.adshield.vpn.packet.IpPacketBuilder
import com.adshield.vpn.packet.IpPacketParser
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

/**
 * Reads packets from the tunnel, answers DNS (UDP/53) through [processor], resets TCP SYNs (we only
 * serve DNS), and drops everything else. Concurrency is bounded: when too many queries are in flight,
 * new ones are dropped and the client's resolver simply retries.
 *
 * [run] returns normally when the interface dies by itself (the caller should recover) and throws
 * CancellationException when cancelled (it closes [pfd] first, which unblocks the blocking read).
 */
class TunnelLoop(
    private val processor: DnsQueryProcessor,
    private val attribute: (UdpPacket) -> String?,
) {
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
            is IpPacketParser.Result.Udp -> {
                val packet = parsed.packet
                if (packet.dstPort != DNS_PORT || !inflight.tryAcquire()) return
                scope.launch(Dispatchers.Default) {
                    try {
                        answer(packet, outbound)
                    } finally {
                        inflight.release()
                    }
                }
            }
            is IpPacketParser.Result.Syn -> outbound.trySend(IpPacketBuilder.tcpResetFor(parsed.syn))
            null -> Unit
        }
    }

    private suspend fun answer(packet: UdpPacket, outbound: Channel<ByteArray>) {
        val response = processor.process(packet.payload, attribute(packet)) ?: return
        val mtuLimit = VpnConfig.MTU - if (packet.isIpv6) 48 else 28
        val limit = minOf(mtuLimit, DnsParser.clientUdpLimit(packet.payload))
        val payload = if (response.size > limit) DnsResponseBuilder.truncate(response) ?: return else response
        outbound.trySend(IpPacketBuilder.udpReply(packet, payload))
    }

    private companion object {
        const val DNS_PORT = 53
        const val BUFFER = 32 * 1024
        const val OUT_CAPACITY = 256
        const val MAX_INFLIGHT = 64
    }
}
