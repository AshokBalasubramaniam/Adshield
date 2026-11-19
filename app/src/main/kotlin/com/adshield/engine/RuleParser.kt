package com.adshield.engine

import java.io.BufferedReader

/**
 * Parses public filter lists into plain domains. Supported syntaxes:
 *  - hosts files:        `0.0.0.0 ads.example.com`
 *  - plain domain lists: `ads.example.com`
 *  - simple Adblock:     `||ads.example.com^`
 * Anything else (cosmetic rules, URL paths, wildcards, regexes) is counted as rejected and ignored,
 * because DNS filtering can only act on whole host names.
 */
object RuleParser {
    /** [ignored]: valid entries DNS cannot act on (IP literals). [rejected]: malformed or unsupported syntax. */
    data class Stats(val lines: Int, val accepted: Int, val rejected: Int, val ignored: Int = 0)

    private val HOSTS_IPS = setOf("0.0.0.0", "127.0.0.1", "::", "::1", "0", "255.255.255.255")
    private val IGNORED = setOf(
        "localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback",
        "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0",
    )

    fun parse(reader: BufferedReader, onDomain: (String) -> Unit): Stats {
        var lines = 0
        var accepted = 0
        var rejected = 0
        var ignored = 0
        while (true) {
            val raw = reader.readLine() ?: break
            lines++
            val line = stripComment(raw).trim()
            if (line.isEmpty() || line.startsWith("!") || line.startsWith("[")) continue
            val domains = extract(line)
            if (domains == null) {
                rejected++
                continue
            }
            for (d in domains) {
                if (d in IGNORED) continue
                if (isIpLiteral(d)) {
                    ignored++
                    continue
                }
                val n = DomainNormalizer.normalizeRuleDomain(d)
                if (n == null) {
                    rejected++
                } else {
                    accepted++
                    onDomain(n)
                }
            }
        }
        return Stats(lines, accepted, rejected, ignored)
    }

    fun parse(text: String, onDomain: (String) -> Unit): Stats = parse(text.reader().buffered(), onDomain)

    private fun isIpLiteral(d: String): Boolean =
        ':' in d || (d.isNotEmpty() && d.all { it in '0'..'9' || it == '.' })

    private fun stripComment(line: String): String {
        val i = line.indexOf('#')
        return if (i >= 0) line.substring(0, i) else line
    }

    private fun extract(line: String): List<String>? {
        if (line.startsWith("||")) {
            val end = line.indexOf('^')
            if (end < 3) return null
            val rest = line.substring(end + 1)
            if (rest.isNotEmpty() && rest != "$important") return null
            val d = line.substring(2, end)
            return if ('/' in d || '*' in d || ':' in d) null else listOf(d)
        }
        val tokens = line.split(' ', '\t').filter { it.isNotEmpty() }
        return when {
            tokens.isEmpty() -> emptyList()
            tokens[0] in HOSTS_IPS && tokens.size >= 2 -> tokens.drop(1)
            tokens.size == 1 && !tokens[0].startsWith("@@") && '/' !in tokens[0] && '*' !in tokens[0] -> tokens
            else -> null
        }
    }

    private const val important = "\$important"
}
