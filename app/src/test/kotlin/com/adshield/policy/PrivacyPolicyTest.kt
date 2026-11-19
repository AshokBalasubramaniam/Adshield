package com.adshield.policy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Regression guards for the privacy requirements. They fail the build if someone adds a forbidden
 * permission, analytics/advertising dependency, cleartext traffic, or disables TLS validation.
 */
class PrivacyPolicyTest {
    private fun module(path: String) = File(path).takeIf { it.exists() } ?: File("app/$path")
    /** Manifest without XML comments, so words in explanations are not mistaken for declarations. */
    private val manifest get() = module("src/main/AndroidManifest.xml").readText().replace(Regex("<!--.*?-->", RegexOption.DOT_MATCHES_ALL), "")
    private val sources get() = module("src/main/kotlin").walkTopDown().filter { it.extension == "kt" }.toList()

    /** Kotlin source without comments (block, KDoc and full-line //), so only executable code is inspected. */
    private fun code(f: File): String = f.readText()
        .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "")
        .lines().filterNot { it.trimStart().startsWith("//") }.joinToString("\n")

    @Test fun requestsExactlyTheMinimumPermissions() {
        val perms = Regex("""<uses-permission\s+android:name="([^"]+)"""").findAll(manifest).map { it.groupValues[1] }.toSet()
        assertEquals(
            setOf(
                "android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE", "android.permission.FOREGROUND_SERVICE",
                "android.permission.FOREGROUND_SERVICE_SPECIAL_USE", "android.permission.POST_NOTIFICATIONS",
            ),
            perms,
        )
    }

    @Test fun noForbiddenPermissionsOrBroadPackageVisibility() {
        listOf("LOCATION", "CONTACTS", "STORAGE", "READ_PHONE", "READ_SMS", "CAMERA", "RECORD_AUDIO", "QUERY_ALL_PACKAGES", "AD_ID", "WAKE_LOCK", "RECEIVE_BOOT").forEach {
            assertFalse("manifest must not mention $it", manifest.contains(it))
        }
    }

    @Test fun cleartextIsOffAndBackupIsOff() {
        assertTrue(manifest.contains("""android:usesCleartextTraffic="false""""))
        assertTrue(manifest.contains("""android:allowBackup="false""""))
        val nsc = module("src/main/res/xml/network_security_config.xml").readText()
        assertTrue(nsc.contains("""cleartextTrafficPermitted="false""""))
        assertFalse("user-added CAs must not be trusted", nsc.contains("""src="user""""))
        assertFalse(nsc.contains("debug-overrides"))
    }

    @Test fun noAnalyticsOrAdvertisingDependencies() {
        val catalog = File("../gradle/libs.versions.toml").takeIf { it.exists() } ?: File("gradle/libs.versions.toml")
        val build = module("build.gradle.kts").readText()
        val text = (catalog.readText() + build).lowercase()
        listOf("firebase", "play-services", "gms", "crashlytics", "appsflyer", "adjust", "mixpanel", "amplitude", "segment", "flurry", "admob", "applovin", "facebook", "sentry", "bugsnag", "datadog", "newrelic", "okhttp", "retrofit")
            .forEach { assertFalse("forbidden dependency: $it", text.contains(it)) }
    }

    @Test fun neverWeakensTlsValidation() {
        val banned = listOf("TrustManager", "X509", "HostnameVerifier", "setHostnameVerifier", "SSLContext", "setDefaultHostnameVerifier", "ALLOW_ALL", "SSLSocketFactory")
        sources.forEach { f ->
            val t = code(f)
            banned.forEach { assertFalse("${f.name} must not use $it", t.contains(it)) }
        }
    }

    @Test fun noFixedRemoteEndpointsExceptFilterListPublishers() {
        val urlRegex = Regex("""https?://[A-Za-z0-9._\-]+""")
        val allowedHosts = setOf(
            "raw.githubusercontent.com", "malware-filter.gitlab.io", "cloudflare-dns.com", // lists + default DoH choice
            "creativecommons.org", "www.mozilla.org", "dns.example", "lists.example", // docs/examples only
        )
        sources.filter { it.name != "BuiltInLists.kt" && it.name != "DnsSettings.kt" }.forEach { f ->
            urlRegex.findAll(code(f)).map { it.value.substringAfter("://") }.forEach { host ->
                if (host !in allowedHosts && !host.endsWith(".example")) assertTrue("${f.name} references unexpected host $host", false)
            }
        }
    }

    @Test fun vpnServiceAddsOnlyDnsRoutesNeverADefaultRoute() {
        val svc = code(module("src/main/kotlin/com/adshield/vpn/AdShieldVpnService.kt"))
        assertFalse("a 0.0.0.0/0 or ::/0 route would send all traffic through the tunnel", Regex("""addRoute\("(0\.0\.0\.0|::)"""").containsMatchIn(svc))
        assertFalse(svc.contains("allowBypass"))
        assertTrue("AdShield's own traffic must be excluded from its tunnel", svc.contains("addDisallowedApplication(packageName)"))
    }
}
