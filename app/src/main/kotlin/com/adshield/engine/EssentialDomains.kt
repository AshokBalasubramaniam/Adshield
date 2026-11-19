package com.adshield.engine

/**
 * Built-in safety net: domains a *public list* may never block. A user's own block rule still wins.
 *
 * Two tiers:
 *  - [core]: video CDNs, DRM licensing, connectivity checks, platform services. Always protected.
 *  - [streamingFirstParty]: first-party hosts of streaming apps (authentication, playback APIs and DRM
 *    licence endpoints live here, next to ad/analytics hosts such as `videoads.hotstar.com`).
 *    Protected by default; the user may relax this ("Aggressive streaming mode") at the risk of broken playback.
 *
 * Consequence (disclosed in the UI): with the default setting, first-party ad hosts of these services
 * cannot be removed by DNS filtering.
 */
object EssentialDomains {
    /** Matches the domain and all of its subdomains. */
    val coreSuffixes: DomainSet = DomainSet.of(
        // Video delivery, thumbnails, avatars
        "googlevideo.com", "ytimg.com", "ggpht.com", "gstatic.com",
        // DRM licensing
        "widevine.com",
        // Connectivity checks / captive portal detection
        "msftconnecttest.com", "msftncsi.com", "captive.apple.com", "connectivitycheck.android.com",
        "nmcheck.gnome.org", "detectportal.firefox.com",
        // Platform, push and sign-in
        "play.googleapis.com", "android.clients.google.com", "mtalk.google.com", "firebaseinstallations.googleapis.com",
        "fcm.googleapis.com", "accounts.google.com", "android.apis.google.com",
    )

    /** YouTube first-party domain (suffix match); governed by the YouTube profile. */
    val youtubeFirstParty: DomainSet = DomainSet.of("youtube.com")

    /** Other streaming-service first-party domains (suffix match). */
    val streamingFirstParty: DomainSet = DomainSet.of("hotstar.com", "jiohotstar.com", "jiocinema.com", "hotstarext.com")

    /** Match only that exact host; their parent domains also host ad services. */
    val exact: Set<String> = setOf(
        "google.com", "www.google.com", "play.google.com", "clients3.google.com", "clients4.google.com",
        "connectivitycheck.gstatic.com", "android.com", "www.android.com", "dl.google.com",
    )

    fun isEssential(
        domain: String,
        suffixes: DomainSet.Suffixes,
        protectStreamingFirstParty: Boolean = true,
        protectYoutubeFirstParty: Boolean = true,
    ): Boolean =
        domain in exact || coreSuffixes.findMatch(suffixes) != null ||
            (protectStreamingFirstParty && streamingFirstParty.findMatch(suffixes) != null) ||
            (protectYoutubeFirstParty && youtubeFirstParty.findMatch(suffixes) != null)

    fun isEssential(domain: String, protectStreamingFirstParty: Boolean = true, protectYoutubeFirstParty: Boolean = true): Boolean =
        domain in exact || coreSuffixes.contains(domain) ||
            (protectStreamingFirstParty && streamingFirstParty.contains(domain)) ||
            (protectYoutubeFirstParty && youtubeFirstParty.contains(domain))
}
