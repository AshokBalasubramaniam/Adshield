package com.adshield.domain.model

enum class CompatLevel(val label: String) {
    /** Some separate ad/tracking domains can be blocked; in-stream ads are not expected to be removed. */
    LIMITED("Limited · not verified"),

    /** Ads come from separate ad-network domains, which DNS filtering handles well. */
    NETWORK_ADS("Ad networks blocked"),
}

data class CompatEntry(
    val name: String,
    val packages: List<String>,
    val level: CompatLevel,
    val summary: String,
    val details: List<String>,
)

/**
 * Honest, static compatibility statements. AdShield has not been verified against any specific
 * version of these apps, so none of them is ever shown as "fully blocked".
 */
object AppCompatibility {
    val youtube = CompatEntry(
        name = "YouTube",
        packages = listOf("com.google.android.youtube", "com.google.android.apps.youtube.music"),
        level = CompatLevel.LIMITED,
        summary = "In-stream video ads are normally delivered together with the video, so DNS filtering cannot remove them.",
        details = listOf(
            "AdShield blocks separate Google ad and tracking domains (for example doubleclick.net, googlesyndication.com).",
            "Video delivery (googlevideo.com), thumbnails and sign-in are always protected and never blocked.",
            "Ads that arrive from the same servers as the video cannot be told apart at DNS level and will still play.",
            "More → YouTube protection shows, from real lookups on this phone, which hosts YouTube asked for and which rule allowed or blocked each. Use it to check results yourself.",
            "Not verified to remove ads in any YouTube version. Results can change with every app update.",
        ),
    )

    val hotstar = CompatEntry(
        name = "JioHotstar / Hotstar",
        packages = listOf("in.startv.hotstar", "in.startv.hotstar.dplus", "com.jio.media.ondemand"),
        level = CompatLevel.LIMITED,
        summary = "Streaming apps commonly insert ads into the video stream itself, which DNS filtering cannot separate.",
        details = listOf(
            "AdShield blocks third-party ad and analytics networks that appear in public filter lists.",
            "By default, Hotstar's own first-party hosts are protected, because sign-in, playback and DRM licensing share them. That also means first-party ad hosts are not blocked.",
            "Advanced users can switch on “Aggressive streaming mode” in DNS settings. This may break playback, and AdShield cannot predict which hosts will matter.",
            "AdShield never bypasses subscriptions, DRM or ad-free requirements, and never fakes ad completion.",
            "Not verified to remove ads in any Hotstar version.",
        ),
    )

    val others = CompatEntry(
        name = "Other apps, browsers and games",
        packages = emptyList(),
        level = CompatLevel.NETWORK_ADS,
        summary = "Best results when ads come from separate ad-network domains.",
        details = listOf(
            "Ads served from the same domain as content (first-party ads, sponsored posts in social feeds, ads stitched into streams) cannot be blocked.",
            "Rewarded-ad games may fail to load ads. AdShield does not fake completion, so rewards can be unavailable.",
            "Apps that use their own encrypted DNS (DNS-over-HTTPS or DNS-over-TLS) bypass DNS filtering; AdShield cannot inspect encrypted traffic and never decrypts HTTPS.",
        ),
    )

    val featured = listOf(youtube, hotstar)
}
