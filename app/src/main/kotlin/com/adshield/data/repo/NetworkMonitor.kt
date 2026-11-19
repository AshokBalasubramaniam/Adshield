package com.adshield.data.repo

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import com.adshield.domain.model.ConnectionType
import com.adshield.domain.model.NetworkStatus
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.conflate
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.shareIn
import java.net.Inet6Address
import java.net.InetAddress
import javax.inject.Inject
import javax.inject.Singleton

/** The best physical (non-VPN) network right now. [network] is null when offline. */
class Underlying(
    val network: Network?,
    val status: NetworkStatus,
    val dnsServers: List<InetAddress>,
)

/**
 * Tracks the physical network underneath the VPN. AdShield binds its upstream DNS sockets to this
 * network, so upstream queries can never loop back into the tunnel and never use a different path.
 */
@Singleton
class NetworkMonitor @Inject constructor(
    @ApplicationContext context: Context,
    scope: CoroutineScope,
) {
    private val cm = context.getSystemService(ConnectivityManager::class.java)

    private class Info(var caps: NetworkCapabilities? = null, var lp: LinkProperties? = null)

    val underlying: SharedFlow<Underlying> = callbackFlow {
        val nets = LinkedHashMap<Network, Info>()
        fun emit() {
            val best = synchronized(nets) {
                nets.entries.filter { it.value.caps != null }.maxByOrNull { rank(it.value.caps!!) }
                    ?.let { Triple(it.key, it.value.caps!!, it.value.lp) }
            }
            trySend(toUnderlying(best))
        }
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                synchronized(nets) { nets.getOrPut(network) { Info() } }
            }
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                synchronized(nets) { nets.getOrPut(network) { Info() }.caps = caps }
                emit()
            }
            override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) {
                synchronized(nets) { nets.getOrPut(network) { Info() }.lp = lp }
                emit()
            }
            override fun onLost(network: Network) {
                synchronized(nets) { nets.remove(network) }
                emit()
            }
        }
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        cm.registerNetworkCallback(request, cb)
        trySend(toUnderlying(null))
        awaitClose { runCatching { cm.unregisterNetworkCallback(cb) } }
    }.conflate().shareIn(scope, SharingStarted.WhileSubscribed(5_000), replay = 1)

    val status: Flow<NetworkStatus> = underlying.map { it.status }

    private fun rank(c: NetworkCapabilities): Int {
        var r = 0
        if (c.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) r += 100
        r += when {
            c.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 30
            c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 20
            c.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> 10
            else -> 0
        }
        return r
    }

    private fun toUnderlying(best: Triple<Network, NetworkCapabilities, LinkProperties?>?): Underlying {
        if (best == null) return Underlying(null, NetworkStatus(), emptyList())
        val (network, caps, lp) = best
        val type = when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> ConnectionType.WIFI
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> ConnectionType.CELLULAR
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> ConnectionType.ETHERNET
            else -> ConnectionType.OTHER
        }
        val dns = lp?.dnsServers.orEmpty()
        val v6 = lp?.linkAddresses.orEmpty().any { it.address is Inet6Address && !it.address.isLinkLocalAddress }
        return Underlying(
            network = network,
            status = NetworkStatus(
                type = type,
                validated = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
                metered = !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED),
                dnsServers = dns.mapNotNull { it.hostAddress },
                ipv6Available = v6,
            ),
            dnsServers = dns,
        )
    }
}
