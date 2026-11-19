package com.adshield.dns

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL

/** Resolves a raw DNS query against some upstream. Returns null when no answer could be obtained. */
fun interface DnsUpstream {
    suspend fun resolve(query: ByteArray): ByteArray?
}

/**
 * Classic DNS over UDP with TCP retry when the answer is truncated.
 * Sockets are handed to [bindUdp]/[bindTcp] before use so the caller can pin them to the physical
 * (non-VPN) network; this is what prevents the upstream query from looping back into the tunnel.
 */
class UdpTcpDnsUpstream(
    private val servers: () -> List<InetAddress>,
    private val bindUdp: (DatagramSocket) -> Unit,
    private val bindTcp: (Socket) -> Unit,
    private val timeoutMs: Int = 2500,
    private val port: Int = DNS_PORT,
) : DnsUpstream {

    override suspend fun resolve(query: ByteArray): ByteArray? = withContext(Dispatchers.IO) {
        for (server in servers()) {
            val udp = try {
                queryUdp(server, query)
            } catch (_: IOException) {
                null
            }
            if (udp != null) {
                if (!DnsParser.isTruncated(udp)) return@withContext udp
                val tcp = try {
                    queryTcp(server, query)
                } catch (_: IOException) {
                    null
                }
                return@withContext tcp ?: udp
            }
        }
        null
    }

    private fun queryUdp(server: InetAddress, query: ByteArray): ByteArray? {
        DatagramSocket().use { socket ->
            bindUdp(socket)
            socket.soTimeout = timeoutMs
            socket.connect(InetSocketAddress(server, port))
            socket.send(DatagramPacket(query, query.size))
            val buf = ByteArray(MAX_UDP_RESPONSE)
            val packet = DatagramPacket(buf, buf.size)
            while (true) {
                socket.receive(packet)
                val resp = buf.copyOf(packet.length)
                // Accept only a response with the matching transaction id (anti-spoofing hygiene).
                if (resp.size >= DnsParser.HEADER_SIZE && resp[0] == query[0] && resp[1] == query[1]) return resp
            }
        }
    }

    private fun queryTcp(server: InetAddress, query: ByteArray): ByteArray? {
        Socket().use { socket ->
            bindTcp(socket)
            socket.soTimeout = timeoutMs
            socket.connect(InetSocketAddress(server, port), timeoutMs)
            val out = DataOutputStream(socket.getOutputStream())
            out.writeShort(query.size)
            out.write(query)
            out.flush()
            val input = DataInputStream(socket.getInputStream())
            val len = input.readUnsignedShort()
            if (len < DnsParser.HEADER_SIZE) return null
            val resp = ByteArray(len)
            input.readFully(resp)
            return if (resp[0] == query[0] && resp[1] == query[1]) resp else null
        }
    }

    private companion object {
        const val DNS_PORT = 53
        const val MAX_UDP_RESPONSE = 4096
    }
}

/**
 * RFC 8484 DNS-over-HTTPS (POST, application/dns-message). Uses the platform TLS stack with default
 * certificate and host-name validation; there is deliberately no way to relax it.
 */
class DohDnsUpstream(
    url: String,
    private val open: (URL) -> HttpURLConnection,
    private val timeoutMs: Int = 4000,
) : DnsUpstream {
    private val endpoint: URL = validate(url)

    override suspend fun resolve(query: ByteArray): ByteArray? = withContext(Dispatchers.IO) {
        try {
            val conn = open(endpoint)
            try {
                conn.requestMethod = "POST"
                conn.connectTimeout = timeoutMs
                conn.readTimeout = timeoutMs
                conn.instanceFollowRedirects = false
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/dns-message")
                conn.setRequestProperty("Accept", "application/dns-message")
                conn.outputStream.use { it.write(query) }
                if (conn.responseCode != HttpURLConnection.HTTP_OK) return@withContext null
                val body = conn.inputStream.use { readBounded(it, MAX_RESPONSE) } ?: return@withContext null
                if (body.size < DnsParser.HEADER_SIZE) return@withContext null
                body
            } finally {
                conn.disconnect()
            }
        } catch (_: IOException) {
            null
        }
    }

    companion object {
        private const val MAX_RESPONSE = 65_535

        /** Reads at most [limit] bytes; returns null if the stream holds more (API 29 safe: no readNBytes). */
        internal fun readBounded(input: java.io.InputStream, limit: Int): ByteArray? {
            val out = java.io.ByteArrayOutputStream()
            val buf = ByteArray(4096)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                if (out.size() + n > limit) return null
                out.write(buf, 0, n)
            }
            return out.toByteArray()
        }

        /** Accepts only well-formed https URLs with a host. Throws IllegalArgumentException otherwise. */
        fun validate(url: String): URL {
            val parsed = try {
                URL(url.trim())
            } catch (e: java.net.MalformedURLException) {
                throw IllegalArgumentException("Not a valid URL", e)
            }
            require(parsed.protocol == "https") { "DNS-over-HTTPS requires an https:// URL" }
            require(!parsed.host.isNullOrBlank()) { "URL has no host" }
            require(parsed.userInfo == null) { "Credentials in URL are not allowed" }
            return parsed
        }

        fun isValid(url: String): Boolean = runCatching { validate(url) }.isSuccess
    }
}
