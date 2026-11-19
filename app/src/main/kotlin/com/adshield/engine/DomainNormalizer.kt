package com.adshield.engine

import java.util.Locale

/** Domain syntax validation and normalisation. Never throws. */
object DomainNormalizer {
    private const val MAX_NAME = 253
    private const val MAX_LABEL = 63

    /**
     * Lower-cases, strips a trailing dot and validates host-name syntax (letters, digits, '-' and '_').
     * Returns null for anything that is not a syntactically valid name.
     */
    fun normalize(raw: String): String? {
        var s = raw.trim().lowercase(Locale.ROOT)
        if (s.endsWith(".")) s = s.dropLast(1)
        if (s.isEmpty() || s.length > MAX_NAME) return null
        var labelLen = 0
        var prev = '.'
        for (c in s) {
            if (c == '.') {
                if (labelLen == 0) return null
                if (prev == '-') return null
                labelLen = 0
            } else {
                val ok = c in 'a'..'z' || c in '0'..'9' || c == '-' || c == '_'
                if (!ok) return null
                if (labelLen == 0 && c == '-') return null
                labelLen++
                if (labelLen > MAX_LABEL) return null
            }
            prev = c
        }
        if (labelLen == 0 || prev == '-') return null
        return s
    }

    /** Stricter check used for list entries and user rules: needs a dot, and must not be an IP literal. */
    fun normalizeRuleDomain(raw: String): String? {
        val s = normalize(raw) ?: return null
        val dot = s.lastIndexOf('.')
        if (dot <= 0) return null
        val tld = s.substring(dot + 1)
        if (tld.all { it in '0'..'9' }) return null // IPv4 literal or numeric junk
        return s
    }
}
