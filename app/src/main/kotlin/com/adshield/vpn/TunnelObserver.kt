package com.adshield.vpn

/**
 * Passive hooks for DNS-bypass diagnostics. Calls happen on the packet path, so implementations must be
 * cheap and must not block. Only counts and addresses of *resolvers* are reported, never domain names.
 */
interface TunnelObserver {
    /** A plain-DNS query reached a captured public resolver (the app hard-codes its DNS server). */
    fun onHardcodedResolverQuery(resolver: ByteArray) {}

    /** TCP to a captured address other than port 53 was refused, e.g. DNS-over-TLS (853) or DoH (443). */
    fun onRefusedTcp(dst: ByteArray, port: Int) {}

    /** A UDP packet to a captured address other than port 53 was dropped, e.g. DNS-over-QUIC or QUIC to a resolver. */
    fun onDroppedUdp(dst: ByteArray, port: Int) {}

    companion object {
        val NONE = object : TunnelObserver {}
    }
}
