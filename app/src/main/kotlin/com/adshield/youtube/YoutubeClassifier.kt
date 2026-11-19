package com.adshield.youtube

import com.adshield.engine.DomainSet

/**
 * What a DNS name *is* in YouTube's delivery chain. Used only to explain decisions and to scope the
 * diagnostic log; it never decides blocking (the filtering engine does that).
 *
 * [mayCarrySameOriginAds]: true where ad content can share the host with the video/API, so a DNS decision
 * cannot tell ad traffic from content traffic.
 */
enum class YoutubeClass(
    val label: String,
    val playbackCritical: Boolean,
    val mayCarrySameOriginAds: Boolean,
    val explanation: String,
) {
    VIDEO_CDN("Video delivery", true, true, "Streams video and audio, ads included when they are stitched into the stream. Never blocked."),
    FIRST_PARTY("YouTube API / site", true, true, "Player API, search, comments, recommendations and sign-in state. Ad placement data travels here too, but it is mixed with content."),
    THUMBNAILS("Thumbnails / avatars", true, false, "Images. Never blocked."),
    AUTH("Sign-in / account", true, false, "Authentication and account services."),
    STATIC_ASSETS("Static assets", true, false, "Shared Google static content (scripts, fonts, images)."),
    AD_SERVING("Separate ad serving", false, false, "Dedicated advertising domains. Blocking the lookup can stop an ad request, but it does not prove an ad was removed."),
    ANALYTICS("Analytics / tracking", false, false, "Measurement and tracking endpoints. Blocking is usually safe."),
    OTHER_GOOGLE("Other Google infrastructure", false, false, "Generic Google hosts. Context-dependent, so not recorded unless the lookup is tied to YouTube."),
    OTHER("Other", false, false, "Not YouTube-related by name."),
}

object YoutubeClassifier {
    /** Packages treated as "the YouTube app" for detection and attribution. */
    const val APP_PACKAGE = "com.google.android.youtube"
    val APP_PACKAGES = setOf(APP_PACKAGE, "com.google.android.apps.youtube.music")

    private val videoCdn = DomainSet.of("googlevideo.com")
    private val thumbs = DomainSet.of("ytimg.com", "ggpht.com", "googleusercontent.com")
    private val firstParty = DomainSet.of(
        "youtube.com", "youtu.be", "youtube-nocookie.com", "youtubei.googleapis.com", "youtube.googleapis.com",
        "youtubeembeddedplayer.googleapis.com", "youtubekids.com",
    )
    private val auth = DomainSet.of("accounts.google.com", "oauth2.googleapis.com", "www.googleapis.com", "android.clients.google.com", "play.googleapis.com")
    private val statics = DomainSet.of("gstatic.com")
    private val ads = DomainSet.of(
        "doubleclick.net", "googlesyndication.com", "googleadservices.com", "2mdn.net", "googletagservices.com",
        "adservice.google.com", "admob.com",
    )
    private val analytics = DomainSet.of("google-analytics.com", "app-measurement.com", "googletagmanager.com", "analytics.google.com")
    private val google = DomainSet.of("google.com", "googleapis.com", "gvt1.com", "gvt2.com", "1e100.net")

    /** Order matters: most specific first (e.g. youtubei.googleapis.com before googleapis.com). */
    fun classify(domain: String): YoutubeClass = when {
        videoCdn.contains(domain) -> YoutubeClass.VIDEO_CDN
        ads.contains(domain) -> YoutubeClass.AD_SERVING
        analytics.contains(domain) -> YoutubeClass.ANALYTICS
        firstParty.contains(domain) -> YoutubeClass.FIRST_PARTY
        thumbs.contains(domain) -> YoutubeClass.THUMBNAILS
        auth.contains(domain) -> YoutubeClass.AUTH
        statics.contains(domain) -> YoutubeClass.STATIC_ASSETS
        google.contains(domain) -> YoutubeClass.OTHER_GOOGLE
        else -> YoutubeClass.OTHER
    }

    /** Whether a lookup is worth recording in the YouTube diagnostic log. */
    fun isYoutubeRelated(cls: YoutubeClass, attributedPackage: String?): Boolean =
        (attributedPackage != null && attributedPackage in APP_PACKAGES) ||
            (cls != YoutubeClass.OTHER && cls != YoutubeClass.OTHER_GOOGLE)
}
