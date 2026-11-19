package com.adshield.domain.model

/** Why a domain was blocked. Order of declaration is the order used to label a domain found in several lists. */
enum class BlockCategory(val label: String) {
    MALWARE("Malware"),
    PHISHING("Phishing"),
    TRACKER("Trackers"),
    ADS("Ads"),
    CUSTOM("Custom rule"),
}

enum class AllowReason { NO_MATCH, ESSENTIAL, USER_GLOBAL, USER_APP }

sealed interface FilterDecision {
    data class Allow(val reason: AllowReason) : FilterDecision
    data class Block(val category: BlockCategory, val matchedRule: String) : FilterDecision
}

/** How a blocked DNS query is answered. */
enum class BlockMode(val label: String, val description: String) {
    NULL_IP("Null address", "Answers A/AAAA with 0.0.0.0 / :: so apps fail fast without waiting for a timeout."),
    NXDOMAIN("NXDOMAIN", "Answers that the domain does not exist."),
}

enum class UpstreamMode(val label: String) {
    SYSTEM("Network's DNS servers"),
    CUSTOM("Custom DNS server (UDP/TCP)"),
    DOH("DNS-over-HTTPS"),
}

enum class ConnectionType(val label: String) {
    WIFI("Wi-Fi"),
    CELLULAR("Mobile data"),
    ETHERNET("Ethernet"),
    OTHER("Other"),
    NONE("No connection"),
}

sealed interface ProtectionState {
    data object Stopped : ProtectionState
    data class Starting(val detail: String = "Starting") : ProtectionState
    data object Running : ProtectionState
    data class Error(val message: String) : ProtectionState
}

data class NetworkStatus(
    val type: ConnectionType = ConnectionType.NONE,
    val validated: Boolean = false,
    val metered: Boolean = true,
    val dnsServers: List<String> = emptyList(),
    val ipv6Available: Boolean = false,
)

data class UserRule(
    val id: Long = 0,
    val domain: String,
    val isAllow: Boolean,
    /** Empty string means the rule is global. */
    val packageName: String = "",
)

data class BlocklistSource(
    val id: String,
    val name: String,
    val description: String,
    val url: String?,
    val category: BlockCategory,
    val enabled: Boolean,
    val builtIn: Boolean,
    val license: String,
    val domainCount: Int,
    val sha256: String?,
    val updatedAt: Long,
    val lastError: String?,
    val sizeNote: String = "",
)

data class StatsTotals(
    val totalQueries: Long = 0,
    val allowed: Long = 0,
    val cacheHits: Long = 0,
    val failures: Long = 0,
    val ads: Long = 0,
    val trackers: Long = 0,
    val malware: Long = 0,
    val phishing: Long = 0,
    val custom: Long = 0,
) {
    val blocked: Long get() = ads + trackers + malware + phishing + custom
}

data class AppStat(val packageName: String, val total: Long, val blocked: Long)

data class DayStat(val epochDay: Long, val total: Long, val blocked: Long)

data class InstalledApp(val packageName: String, val label: String, val filteringEnabled: Boolean)

data class EngineStatus(
    val loaded: Boolean = false,
    val domainCount: Int = 0,
    val loadedAtMillis: Long = 0,
    val loading: Boolean = false,
    val lastError: String? = null,
)
