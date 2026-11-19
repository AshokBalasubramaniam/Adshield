package com.adshield.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.os.Process
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * Best-effort attribution of a DNS query to an app via ConnectivityManager.getConnectionOwnerUid.
 *
 * Android usually performs DNS for apps in the system resolver, in which case the socket owner is a
 * system uid and the query cannot be attributed. This class detects that (no success after
 * [GIVE_UP_AFTER] attempts) and stops asking, to avoid a wasted binder call per query.
 */
class AppUidResolver(context: Context, private val enabled: () -> Boolean) {
    private val cm = context.getSystemService(ConnectivityManager::class.java)
    private val pm = context.packageManager
    private val uidToPackage = ConcurrentHashMap<Int, String>()
    private val attributed = AtomicInteger()
    private val unattributed = AtomicInteger()

    /** Counters for diagnostics: how many lookups could / could not be tied to an app. */
    val attributedCount: Int get() = attributed.get()
    val unattributedCount: Int get() = unattributed.get()

    /** True once enough lookups were seen and none could be attributed (the system resolver owns the sockets). */
    val systemResolverMasksApps: Boolean get() = attributed.get() == 0 && unattributed.get() >= GIVE_UP_AFTER

    private val probeCounter = AtomicInteger()

    fun resolve(protocol: Int, srcAddr: ByteArray, srcPort: Int, dstAddr: ByteArray, dstPort: Int): String? {
        if (!enabled()) return null
        // After many fruitless attempts stop paying a binder call per query, but keep probing 1 in PROBE_EVERY:
        // some apps (e.g. those with their own resolver) do own their DNS sockets, and a permanent give-up
        // would never notice.
        if (systemResolverMasksApps && probeCounter.incrementAndGet() % PROBE_EVERY != 0) return null
        val uid = try {
            cm.getConnectionOwnerUid(
                protocol,
                InetSocketAddress(InetAddress.getByAddress(srcAddr), srcPort),
                InetSocketAddress(InetAddress.getByAddress(dstAddr), dstPort),
            )
        } catch (_: SecurityException) {
            Process.INVALID_UID
        } catch (_: IllegalArgumentException) {
            Process.INVALID_UID
        }
        if (uid < Process.FIRST_APPLICATION_UID) {
            unattributed.incrementAndGet()
            return null
        }
        val pkg = uidToPackage.getOrPut(uid) { pm.getPackagesForUid(uid)?.firstOrNull() ?: return null }
        attributed.incrementAndGet()
        return pkg
    }

    private companion object {
        const val GIVE_UP_AFTER = 200
        const val PROBE_EVERY = 20
    }
}
