package com.adshield.vpn

/** Addresses of the local, virtual DNS endpoint. They exist only inside the tunnel interface. */
object VpnConfig {
    const val SESSION_NAME = "AdShield"
    const val MTU = 1500

    const val V4_ADDRESS = "10.111.222.1"
    const val V4_DNS = "10.111.222.2"
    const val V6_ADDRESS = "fd53:4144:5348::1"
    const val V6_DNS = "fd53:4144:5348::2"

    /**
     * Popular public resolvers. When "capture known resolvers" is on, these addresses are routed into
     * the tunnel too, so apps that hard-code e.g. 8.8.8.8:53 are still filtered (and cannot leak DNS around
     * AdShield). TCP to these addresses is reset, which makes DoT/DoH-to-IP clients fall back quickly.
     */
    val KNOWN_RESOLVERS_V4 = listOf(
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
        "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15",
    )
    val KNOWN_RESOLVERS_V6 = listOf(
        "2001:4860:4860::8888", "2001:4860:4860::8844", "2606:4700:4700::1111", "2606:4700:4700::1001", "2620:fe::fe",
    )

    private val V4_DNS_BYTES = java.net.InetAddress.getByName(V4_DNS).address
    private val V6_DNS_BYTES = java.net.InetAddress.getByName(V6_DNS).address

    /** True if [addr] is one of AdShield's own virtual DNS addresses (as opposed to a captured public resolver). */
    fun isVirtualDns(addr: ByteArray): Boolean = addr.contentEquals(V4_DNS_BYTES) || addr.contentEquals(V6_DNS_BYTES)

    const val ACTION_START = "com.adshield.action.START"
    const val ACTION_STOP = "com.adshield.action.STOP"
    const val NOTIFICATION_CHANNEL = "protection"
    const val NOTIFICATION_ID = 1
}
