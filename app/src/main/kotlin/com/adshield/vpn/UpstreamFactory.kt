package com.adshield.vpn

import com.adshield.data.repo.Underlying
import com.adshield.data.settings.DnsSettings
import com.adshield.dns.DnsUpstream
import com.adshield.dns.DohDnsUpstream
import com.adshield.dns.UdpTcpDnsUpstream
import com.adshield.domain.model.UpstreamMode
import com.adshield.engine.IpLiteral
import java.net.HttpURLConnection

/**
 * Builds the upstream resolver for the current settings and physical network. All sockets/connections
 * are bound to that network, so upstream traffic never re-enters the VPN and never leaves via another path.
 * Returns null when the settings are unusable or there is no network (queries then fail with SERVFAIL
 * rather than leaking via a different route).
 */
object UpstreamFactory {
    fun create(settings: DnsSettings, underlying: Underlying): DnsUpstream? {
        val net = underlying.network ?: return null
        return when (settings.upstreamMode) {
            UpstreamMode.SYSTEM -> {
                val servers = underlying.dnsServers
                if (servers.isEmpty()) null else UdpTcpDnsUpstream({ servers }, { net.bindSocket(it) }, { net.bindSocket(it) })
            }
            UpstreamMode.CUSTOM -> IpLiteral.parseList(settings.customUpstream)?.let { servers ->
                UdpTcpDnsUpstream({ servers }, { net.bindSocket(it) }, { net.bindSocket(it) })
            }
            UpstreamMode.DOH -> runCatching {
                DohDnsUpstream(settings.dohUrl, { url -> net.openConnection(url) as HttpURLConnection })
            }.getOrNull()
        }
    }
}
