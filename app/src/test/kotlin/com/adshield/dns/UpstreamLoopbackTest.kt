package com.adshield.dns

import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import kotlin.concurrent.thread

/** Real sockets against an in-process fake DNS server on loopback. */
private fun ByteArray.last(n: Int) = copyOfRange(size - n, size)

class UpstreamLoopbackTest {
    private val lo = InetAddress.getLoopbackAddress()
    private val closers = mutableListOf<() -> Unit>()
    @After fun tearDown() = closers.forEach { runCatching { it() } }

    /** UDP and TCP fake servers on the same port number; UDP answers are truncated when [truncate] is set. */
    private fun startServers(truncate: Boolean): Int {
        val udp = DatagramSocket(0, lo).also { s -> closers += { s.close() } }
        val tcp = ServerSocket(udp.localPort, 5, lo).also { s -> closers += { s.close() } }
        thread(isDaemon = true) {
            val buf = ByteArray(512)
            while (!udp.isClosed) {
                val p = DatagramPacket(buf, buf.size)
                try { udp.receive(p) } catch (_: Exception) { return@thread }
                val resp = DnsTestUtil.aResponse(buf.copyOf(p.length))
                if (truncate) resp[2] = (resp[2].toInt() or 0x02).toByte()
                udp.send(DatagramPacket(resp, resp.size, p.socketAddress))
            }
        }
        thread(isDaemon = true) {
            while (!tcp.isClosed) {
                val c = try { tcp.accept() } catch (_: Exception) { return@thread }
                c.use {
                    val i = DataInputStream(it.getInputStream()); val q = ByteArray(i.readUnsignedShort()); i.readFully(q)
                    val r = DnsTestUtil.aResponse(q, ip = byteArrayOf(9, 9, 9, 9))
                    DataOutputStream(it.getOutputStream()).apply { writeShort(r.size); write(r); flush() }
                }
            }
        }
        return udp.localPort
    }

    @Test fun udpRoundTrip() = runBlocking {
        val port = startServers(truncate = false)
        val q = DnsTestUtil.query("example.com", 1, id = 0x0102)
        val r = UdpTcpDnsUpstream({ listOf(lo) }, {}, {}, 1000, port).resolve(q)!!
        assertEquals(0x0102, DnsParser.u16(r, 0)); assertEquals(DnsRcode.NOERROR, DnsParser.rcode(r))
        assertFalse(DnsParser.isTruncated(r)); assertEquals(93, r.last(4)[0].toInt())
    }

    @Test fun truncatedUdpFallsBackToTcp() = runBlocking {
        val port = startServers(truncate = true)
        val r = UdpTcpDnsUpstream({ listOf(lo) }, {}, {}, 1000, port).resolve(DnsTestUtil.query("big.example.com", 1))!!
        assertFalse(DnsParser.isTruncated(r)); assertEquals(9, r.last(4)[0].toInt()) // the TCP server's distinct answer
    }

    @Test fun triesNextServerWhenFirstFails() = runBlocking {
        val port = startServers(truncate = false)
        val dead = InetAddress.getByName("192.0.2.1")
        val r = UdpTcpDnsUpstream({ listOf(dead, lo) }, {}, {}, 300, port).resolve(DnsTestUtil.query("example.com", 1))
        assertTrue(r != null)
    }

    @Test fun bindHooksAreInvokedForEverySocket() = runBlocking {
        val port = startServers(truncate = true)
        var udpBound = 0; var tcpBound = 0
        UdpTcpDnsUpstream({ listOf(lo) }, { udpBound++ }, { tcpBound++ }, 1000, port).resolve(DnsTestUtil.query("example.com", 1))
        assertEquals(1, udpBound); assertEquals(1, tcpBound)
    }

    @Test fun noServersMeansNull() = runBlocking {
        assertNull(UdpTcpDnsUpstream({ emptyList() }, {}, {}, 100).resolve(DnsTestUtil.query("a.com", 1)))
    }

    @Test fun unreachableServerTimesOutToNull() = runBlocking {
        // 192.0.2.0/24 is TEST-NET-1 (RFC 5737): never routable.
        val up = UdpTcpDnsUpstream({ listOf(InetAddress.getByName("192.0.2.1")) }, {}, {}, 200)
        assertNull(up.resolve(DnsTestUtil.query("a.com", 1)))
    }

    @Test fun dohRejectsInsecureAndMalformedUrls() {
        assertFalse(DohDnsUpstream.isValid("http://dns.example/dns-query"))
        assertFalse(DohDnsUpstream.isValid("not a url"))
        assertFalse(DohDnsUpstream.isValid("https://user:pw@dns.example/dns-query"))
        assertFalse(DohDnsUpstream.isValid("ftp://dns.example"))
        assertTrue(DohDnsUpstream.isValid("https://cloudflare-dns.com/dns-query"))
    }
}

class BoundedReadTest {
    @Test fun readsWithinLimit() = assertEquals(10, DohDnsUpstream.readBounded(ByteArray(10).inputStream(), 10)!!.size)
    @Test fun rejectsOverLimit() = assertNull(DohDnsUpstream.readBounded(ByteArray(11).inputStream(), 10))
    @Test fun emptyIsEmpty() = assertEquals(0, DohDnsUpstream.readBounded(ByteArray(0).inputStream(), 10)!!.size)
}
