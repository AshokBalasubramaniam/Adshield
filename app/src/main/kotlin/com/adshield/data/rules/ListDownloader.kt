package com.adshield.data.rules

import com.adshield.engine.DomainSet
import com.adshield.engine.RuleParser
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.DigestInputStream
import java.security.MessageDigest

sealed interface DownloadResult {
    data class Success(val sha256: String, val domainCount: Int) : DownloadResult
    data class Failure(val reason: String) : DownloadResult
}

/**
 * Secure list fetcher. Guarantees:
 *  - HTTPS only (including every redirect hop); default platform certificate validation is never altered.
 *  - Hard size cap and timeouts.
 *  - Content must parse as a domain list (majority of non-comment lines valid) and must not shrink
 *    suspiciously versus the previous version.
 *  - Written to a temp file and atomically moved into place only after validation; SHA-256 of the stored
 *    bytes is returned so the caller can detect later tampering/corruption at load time.
 */
class ListDownloader(
    private val dir: File,
    private val open: (URL) -> HttpURLConnection = { it.openConnection() as HttpURLConnection },
    private val maxBytes: Long = MAX_BYTES,
) {
    init {
        dir.mkdirs()
    }

    fun fileFor(id: String): File = File(dir, "$id.txt")

    suspend fun download(id: String, url: String, previousCount: Int): DownloadResult = withContext(Dispatchers.IO) {
        val tmp = File(dir, "$id.tmp")
        try {
            val start = parseHttps(url) ?: return@withContext DownloadResult.Failure("Only https:// URLs are allowed")
            val sha = fetchToFile(start, tmp)
            val unique = DomainSet.Builder(1024)
            val stats = tmp.bufferedReader().use { RuleParser.parse(it) { d -> unique.add(d) } }
            val count = unique.size
            if (count < MIN_DOMAINS) return@withContext DownloadResult.Failure("List contains too few valid domains ($count)")
            if (stats.rejected > stats.accepted) return@withContext DownloadResult.Failure("File does not look like a domain list")
            if (previousCount >= SHRINK_GUARD_MIN && count < previousCount / 2) {
                return@withContext DownloadResult.Failure("New list is less than half the size of the previous one; keeping the old copy")
            }
            Files.move(tmp.toPath(), fileFor(id).toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
            DownloadResult.Success(sha, count)
        } catch (e: IOException) {
            DownloadResult.Failure(e.message?.take(120) ?: "Network error")
        } finally {
            tmp.delete()
        }
    }

    private fun parseHttps(url: String): URL? = parseAllowedUrl(url)

    private fun fetchToFile(start: URL, out: File): String {
        var current = start
        repeat(MAX_REDIRECTS + 1) {
            val conn = open(current)
            try {
                conn.instanceFollowRedirects = false
                conn.connectTimeout = 15_000
                conn.readTimeout = 30_000
                conn.setRequestProperty("Accept", "text/plain, */*")
                conn.setRequestProperty("User-Agent", "AdShield-ListUpdater")
                when (val code = conn.responseCode) {
                    HttpURLConnection.HTTP_OK -> {
                        val declared = conn.contentLengthLong
                        if (declared > maxBytes) throw IOException("List is larger than the ${maxBytes / 1_000_000} MB limit")
                        return copyLimited(conn, out)
                    }
                    301, 302, 303, 307, 308 -> {
                        val loc = conn.getHeaderField("Location") ?: throw IOException("Redirect without Location")
                        current = parseHttps(URL(current, loc).toString()) ?: throw IOException("Redirect to a non-https URL was refused")
                    }
                    else -> throw IOException("Server returned HTTP $code")
                }
            } finally {
                conn.disconnect()
            }
        }
        throw IOException("Too many redirects")
    }

    private fun copyLimited(conn: HttpURLConnection, out: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        var total = 0L
        DigestInputStream(conn.inputStream, digest).use { input ->
            out.outputStream().buffered().use { sink ->
                val buf = ByteArray(16 * 1024)
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    total += n
                    if (total > maxBytes) throw IOException("List exceeded the ${maxBytes / 1_000_000} MB limit")
                    sink.write(buf, 0, n)
                }
            }
        }
        return digest.digest().toHex()
    }

    companion object {
        const val MAX_BYTES = 30L * 1024 * 1024
        const val MAX_REDIRECTS = 4
        const val MIN_DOMAINS = 10
        const val SHRINK_GUARD_MIN = 1000

        /** The single rule for acceptable list URLs: https, has a host, no embedded credentials. */
        fun parseAllowedUrl(url: String): URL? =
            runCatching { URL(url.trim()) }.getOrNull()?.takeIf { it.protocol == "https" && !it.host.isNullOrBlank() && it.userInfo == null }

        fun sha256Of(file: File): String {
            val digest = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buf = ByteArray(16 * 1024)
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    digest.update(buf, 0, n)
                }
            }
            return digest.digest().toHex()
        }

        private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
    }
}
