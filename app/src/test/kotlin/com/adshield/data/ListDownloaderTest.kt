package com.adshield.data

import com.adshield.data.rules.DownloadResult
import com.adshield.data.rules.ListDownloader
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

class ListDownloaderTest {
    @get:Rule val tmp = TemporaryFolder()

    private class FakeConn(
        url: URL, private val code: Int, private val body: ByteArray = ByteArray(0),
        private val headers: Map<String, String> = emptyMap(), private val declaredLength: Long = body.size.toLong(),
        private val failRead: Boolean = false,
    ) : HttpURLConnection(url) {
        override fun disconnect() = Unit
        override fun usingProxy() = false
        override fun connect() = Unit
        override fun getResponseCode() = code
        override fun getContentLengthLong() = declaredLength
        override fun getHeaderField(name: String?): String? = headers[name]
        override fun getInputStream(): InputStream =
            if (failRead) object : InputStream() { override fun read() = throw IOException("connection reset") } else ByteArrayInputStream(body)
    }

    private fun hosts(n: Int) = (1..n).joinToString("\n", prefix = "# test list\n") { "0.0.0.0 ad$it.example.com" }.toByteArray()
    private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }
    private fun downloader(maxBytes: Long = ListDownloader.MAX_BYTES, open: (URL) -> HttpURLConnection) =
        ListDownloader(tmp.newFolder(), open, maxBytes)

    @Test fun successStoresFileAndReturnsHashOfStoredBytes() = runBlocking {
        val body = hosts(50)
        val d = downloader { FakeConn(it, 200, body) }
        val r = d.download("a", "https://lists.example/a.txt", 0) as DownloadResult.Success
        assertEquals(sha(body), r.sha256); assertEquals(50, r.domainCount)
        assertEquals(r.sha256, ListDownloader.sha256Of(d.fileFor("a")))
    }

    @Test fun refusesPlainHttpAndOtherSchemes() = runBlocking {
        var opened = 0
        val d = downloader { opened++; FakeConn(it, 200, hosts(50)) }
        listOf("http://lists.example/a.txt", "ftp://x/y", "file:///etc/hosts", "not a url", "https://user:pw@lists.example/a").forEach {
            assertTrue(it, d.download("a", it, 0) is DownloadResult.Failure)
        }
        assertEquals("no connection may be opened for rejected URLs", 0, opened)
    }

    @Test fun followsHttpsRedirects() = runBlocking {
        val d = downloader { url ->
            if (url.path == "/old") FakeConn(url, 302, headers = mapOf("Location" to "https://cdn.example/new.txt")) else FakeConn(url, 200, hosts(20))
        }
        assertTrue(d.download("a", "https://lists.example/old", 0) is DownloadResult.Success)
    }

    @Test fun refusesRedirectDowngradeToHttp() = runBlocking {
        val d = downloader { FakeConn(it, 301, headers = mapOf("Location" to "http://evil.example/list.txt")) }
        val r = d.download("a", "https://lists.example/a", 0) as DownloadResult.Failure
        assertTrue(r.reason, "non-https" in r.reason)
        assertFalse(d.fileFor("a").exists())
    }

    @Test fun stopsOnRedirectLoops() = runBlocking {
        val d = downloader { FakeConn(it, 302, headers = mapOf("Location" to "https://lists.example/loop")) }
        assertTrue(d.download("a", "https://lists.example/loop", 0) is DownloadResult.Failure)
    }

    @Test fun enforcesSizeCapFromHeaderAndFromStream() = runBlocking {
        val big = hosts(500)
        val byHeader = downloader(maxBytes = 1000) { FakeConn(it, 200, big, declaredLength = big.size.toLong()) }
        assertTrue(byHeader.download("a", "https://x.example/a", 0) is DownloadResult.Failure)
        val byStream = downloader(maxBytes = 1000) { FakeConn(it, 200, big, declaredLength = -1) } // server lies / chunked
        assertTrue(byStream.download("a", "https://x.example/a", 0) is DownloadResult.Failure)
        assertFalse(byStream.fileFor("a").exists())
    }

    @Test fun rejectsHtmlErrorPagesAndTinyLists() = runBlocking {
        val html = "<html><body>Access denied by proxy<br>please login</body></html>\n".repeat(30).toByteArray()
        assertTrue(downloader { FakeConn(it, 200, html) }.download("a", "https://x.example/a", 0) is DownloadResult.Failure)
        assertTrue(downloader { FakeConn(it, 200, hosts(3)) }.download("a", "https://x.example/a", 0) is DownloadResult.Failure)
    }

    @Test fun serverErrorsAndResetsAreFailuresNotCrashes() = runBlocking {
        assertTrue(downloader { FakeConn(it, 503) }.download("a", "https://x.example/a", 0) is DownloadResult.Failure)
        assertTrue(downloader { FakeConn(it, 200, failRead = true) }.download("a", "https://x.example/a", 0) is DownloadResult.Failure)
    }

    @Test fun shrinkGuardKeepsPreviousCopy() = runBlocking {
        val folder = tmp.newFolder()
        val good = ListDownloader(folder, { FakeConn(it, 200, hosts(3000)) })
        assertTrue(good.download("a", "https://x.example/a", 0) is DownloadResult.Success)
        val before = ListDownloader.sha256Of(good.fileFor("a"))
        val shrunk = ListDownloader(folder, { FakeConn(it, 200, hosts(100)) })
        assertTrue(shrunk.download("a", "https://x.example/a", previousCount = 3000) is DownloadResult.Failure)
        assertEquals("previous list must be untouched", before, ListDownloader.sha256Of(good.fileFor("a")))
        assertFalse("temp file must be cleaned up", java.io.File(folder, "a.tmp").exists())
    }

    @Test fun ipOnlyListsAreNotMistakenForGarbage() = runBlocking {
        val body = ((1..300).joinToString("\n") { "10.0.${it / 250}.${it % 250 + 1}" } + "\n" + (1..30).joinToString("\n") { "bad$it.example.net" }).toByteArray()
        val r = downloader { FakeConn(it, 200, body) }.download("a", "https://x.example/a", 0) as DownloadResult.Success
        assertEquals(30, r.domainCount)
    }
}
