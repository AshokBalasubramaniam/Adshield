package com.adshield.engine

import java.net.InetAddress

/** Parses numeric IPv4/IPv6 literals only; never performs a DNS lookup. */
object IpLiteral {
    private val V4 = Regex("""^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$""")
    private val V6_CHARS = Regex("""^[0-9a-fA-F:.]+$""")

    fun parse(text: String): InetAddress? {
        val s = text.trim()
        val ok = V4.matches(s) || (':' in s && s.count { it == ':' } in 2..7 && V6_CHARS.matches(s))
        if (!ok) return null
        return try {
            InetAddress.getByName(s) // numeric literal: no resolver involved
        } catch (_: java.net.UnknownHostException) {
            null
        }
    }

    /** Comma/space separated list; returns null if any entry is not a literal or the list is empty. */
    fun parseList(text: String): List<InetAddress>? {
        val parts = text.split(',', ' ', ';').map { it.trim() }.filter { it.isNotEmpty() }
        if (parts.isEmpty() || parts.size > 4) return null
        return parts.map { parse(it) ?: return null }
    }
}
