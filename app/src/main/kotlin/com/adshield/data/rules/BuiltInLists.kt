package com.adshield.data.rules

import com.adshield.data.db.BlocklistEntity
import com.adshield.domain.model.BlockCategory

/**
 * Filter lists shipped as defaults. Bundled seeds make blocking work offline on first run;
 * the others are fetched over HTTPS directly from their publishers to the device (no AdShield server exists).
 */
object BuiltInLists {
    val all: List<BlocklistEntity> = listOf(
        BlocklistEntity(
            id = "seed-ads", name = "AdShield ad domains (bundled)",
            description = "Small curated list of major ad networks. Works offline.",
            url = null, category = BlockCategory.ADS.name, enabled = true, builtIn = true,
            license = "Original AdShield list (Apache-2.0)", sortOrder = 0,
        ),
        BlocklistEntity(
            id = "seed-trackers", name = "AdShield tracker domains (bundled)",
            description = "Small curated list of analytics and tracking endpoints. Works offline.",
            url = null, category = BlockCategory.TRACKER.name, enabled = true, builtIn = true,
            license = "Original AdShield list (Apache-2.0)", sortOrder = 1,
        ),
        BlocklistEntity(
            id = "adaway", name = "AdAway default blocklist",
            description = "Mobile ad providers and some analytics. Maintained by the AdAway project.",
            url = "https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt",
            category = BlockCategory.ADS.name, enabled = true, builtIn = true,
            license = "CC BY 3.0", sizeNote = "~250 KB", sortOrder = 2,
        ),
        BlocklistEntity(
            id = "1hosts-lite", name = "1Hosts (Lite)",
            description = "Broad ad, tracker and annoyance domains. Larger list: uses roughly 25 MB of memory while protection is on.",
            url = "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/domains.txt",
            category = BlockCategory.ADS.name, enabled = true, builtIn = true,
            license = "MPL-2.0", sizeNote = "~5 MB", sortOrder = 3,
        ),
        BlocklistEntity(
            id = "urlhaus", name = "URLhaus malware domains",
            description = "Hosts currently serving malware (abuse.ch URLhaus, republished by malware-filter). Updated twice daily.",
            url = "https://malware-filter.gitlab.io/urlhaus-filter/urlhaus-filter-domains-online.txt",
            category = BlockCategory.MALWARE.name, enabled = true, builtIn = true,
            license = "CC0 (abuse.ch URLhaus data)", sizeNote = "~30 KB", sortOrder = 4,
        ),
        BlocklistEntity(
            id = "phishing-filter", name = "Phishing domains",
            description = "Active phishing hosts (OpenPhish, PhishTank, IPThreat via malware-filter). Updated twice daily.",
            url = "https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt",
            category = BlockCategory.PHISHING.name, enabled = true, builtIn = true,
            license = "Mixed upstream feeds (OpenPhish community feed is non-commercial; PhishTank requires attribution)",
            sizeNote = "~500 KB", sortOrder = 5,
        ),
    )
}
