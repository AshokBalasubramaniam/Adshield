package com.adshield.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.os.Process
import android.system.OsConstants
import com.adshield.vpn.packet.UdpPacket
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

    fun resolve(p: UdpPacket): String? {
        if (!enabled()) return null
        if (attributed.get() == 0 && unattributed.get() >= GIVE_UP_AFTER) return null
        val uid = try {
            cm.getConnectionOwnerUid(
                OsConstants.IPPROTO_UDP,
                InetSocketAddress(InetAddress.getByAddress(p.srcAddr), p.srcPort),
                InetSocketAddress(InetAddress.getByAddress(p.dstAddr), p.dstPort),
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
    }
}
